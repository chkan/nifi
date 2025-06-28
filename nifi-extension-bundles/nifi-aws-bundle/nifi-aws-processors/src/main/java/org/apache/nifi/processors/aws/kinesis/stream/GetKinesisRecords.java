package org.apache.nifi.processors.aws.kinesis.stream;

import org.apache.nifi.annotation.behavior.InputRequirement;
import org.apache.nifi.annotation.behavior.Stateful;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.SeeAlso;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.components.AllowableValue;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.components.state.Scope;
import org.apache.nifi.expression.ExpressionLanguageScope;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.util.StandardValidators;
import org.apache.nifi.processors.aws.kinesis.stream.record.AbstractKinesisRecordProcessor;
import org.apache.nifi.processors.aws.v2.AbstractAwsSyncProcessor;
import org.apache.nifi.state.StateMap;
import software.amazon.awssdk.services.kinesis.KinesisClient;
import software.amazon.awssdk.services.kinesis.KinesisClientBuilder;
import software.amazon.awssdk.services.kinesis.model.GetRecordsRequest;
import software.amazon.awssdk.services.kinesis.model.GetRecordsResponse;
import software.amazon.awssdk.services.kinesis.model.GetShardIteratorRequest;
import software.amazon.awssdk.services.kinesis.model.ListShardsRequest;
import software.amazon.awssdk.services.kinesis.model.ListShardsResponse;
import software.amazon.awssdk.services.kinesis.model.Record;
import software.amazon.awssdk.services.kinesis.model.Shard;
import software.amazon.awssdk.services.kinesis.model.ShardIteratorType;

import java.nio.ByteBuffer;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

@Tags({"amazon", "aws", "kinesis", "consume"})
@CapabilityDescription("Reads records from the configured Kinesis stream using the AWS SDK client APIs. " +
        "Each shard is polled on each invocation and sequence numbers are stored in NiFi state.")
@SeeAlso({ConsumeKinesisStream.class, PutKinesisStream.class})
@InputRequirement(InputRequirement.Requirement.INPUT_FORBIDDEN)
@Stateful(scopes = {Scope.CLUSTER}, description = "Stores the last sequence number for each shard of the stream")
public class GetKinesisRecords extends AbstractAwsSyncProcessor<KinesisClient, KinesisClientBuilder> {

    static final PropertyDescriptor KINESIS_STREAM_NAME = PutKinesisStream.KINESIS_STREAM_NAME;

    static final AllowableValue TRIM_HORIZON = new AllowableValue("TRIM_HORIZON", "TRIM_HORIZON", "Start at the earliest data record in the shard");
    static final AllowableValue LATEST = new AllowableValue("LATEST", "LATEST", "Start after the most recent data record in the shard");
    static final AllowableValue AT_TIMESTAMP = new AllowableValue("AT_TIMESTAMP", "AT_TIMESTAMP", "Start from the specified timestamp");

    static final PropertyDescriptor INITIAL_STREAM_POSITION = new PropertyDescriptor.Builder()
            .name("Initial Stream Position")
            .description("Initial position in the stream to read from when no state is present")
            .allowableValues(LATEST, TRIM_HORIZON, AT_TIMESTAMP)
            .defaultValue(LATEST.getValue())
            .required(true)
            .build();

    static final PropertyDescriptor STREAM_POSITION_TIMESTAMP = new PropertyDescriptor.Builder()
            .name("Stream Position Timestamp")
            .description("Timestamp to use with the AT_TIMESTAMP initial position")
            .dependsOn(INITIAL_STREAM_POSITION, AT_TIMESTAMP)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .expressionLanguageSupported(ExpressionLanguageScope.ENVIRONMENT)
            .required(false)
            .build();

    static final PropertyDescriptor TIMESTAMP_FORMAT = new PropertyDescriptor.Builder()
            .name("Timestamp Format")
            .description("Format for parsing the Stream Position Timestamp")
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .defaultValue("yyyy-MM-dd'T'HH:mm:ss'Z'")
            .expressionLanguageSupported(ExpressionLanguageScope.ENVIRONMENT)
            .required(false)
            .build();

    static final PropertyDescriptor BATCH_SIZE = new PropertyDescriptor.Builder()
            .name("Batch Size")
            .description("Maximum number of records to return per shard on each invocation")
            .addValidator(StandardValidators.POSITIVE_INTEGER_VALIDATOR)
            .defaultValue("1000")
            .required(true)
            .build();

    static final List<PropertyDescriptor> PROPERTY_DESCRIPTORS = List.of(
            KINESIS_STREAM_NAME,
            REGION,
            AWS_CREDENTIALS_PROVIDER_SERVICE,
            INITIAL_STREAM_POSITION,
            STREAM_POSITION_TIMESTAMP,
            TIMESTAMP_FORMAT,
            BATCH_SIZE,
            TIMEOUT,
            PROXY_CONFIGURATION_SERVICE,
            ENDPOINT_OVERRIDE
    );

    private volatile List<String> shardIds = Collections.emptyList();

    @Override
    protected List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return PROPERTY_DESCRIPTORS;
    }

    @OnScheduled
    public void onScheduled(final ProcessContext context) {
        final String streamName = context.getProperty(KINESIS_STREAM_NAME).evaluateAttributeExpressions().getValue();
        final KinesisClient client = getClient(context);
        final ListShardsRequest request = ListShardsRequest.builder().streamName(streamName).build();
        final ListShardsResponse response = client.listShards(request);
        shardIds = new ArrayList<>();
        for (Shard shard : response.shards()) {
            shardIds.add(shard.shardId());
        }
    }

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
        if (shardIds.isEmpty()) {
            return;
        }

        final String streamName = context.getProperty(KINESIS_STREAM_NAME).evaluateAttributeExpressions().getValue();
        final int batchSize = context.getProperty(BATCH_SIZE).asInteger();
        final KinesisClient client = getClient(context);

        try {
            final StateMap stateMap = context.getStateManager().getState(Scope.CLUSTER);
            final Map<String, String> updatedState = new HashMap<>(stateMap.toMap());
            final DateTimeFormatter formatter = DateTimeFormatter.ofPattern(
                    context.getProperty(TIMESTAMP_FORMAT).evaluateAttributeExpressions().getValue())
                    .withZone(ZoneId.of("UTC"));

            for (final String shardId : shardIds) {
                final String lastSeq = stateMap.get(shardId);

                final GetShardIteratorRequest.Builder iterBuilder = GetShardIteratorRequest.builder()
                        .streamName(streamName)
                        .shardId(shardId);

                if (lastSeq != null) {
                    iterBuilder.shardIteratorType(ShardIteratorType.AFTER_SEQUENCE_NUMBER)
                            .startingSequenceNumber(lastSeq);
                } else {
                    final String position = context.getProperty(INITIAL_STREAM_POSITION).getValue();
                    final ShardIteratorType type = ShardIteratorType.fromValue(position);
                    iterBuilder.shardIteratorType(type);
                    if (type == ShardIteratorType.AT_TIMESTAMP) {
                        final String ts = context.getProperty(STREAM_POSITION_TIMESTAMP)
                                .evaluateAttributeExpressions().getValue();
                        final Instant timestamp = Instant.from(formatter.parse(ts));
                        iterBuilder.timestamp(timestamp);
                    }
                }

                final String iterator = client.getShardIterator(iterBuilder.build()).shardIterator();
                if (iterator == null) {
                    continue;
                }

                final GetRecordsRequest recordsRequest = GetRecordsRequest.builder()
                        .shardIterator(iterator)
                        .limit(batchSize)
                        .build();
                final GetRecordsResponse recordsResponse = client.getRecords(recordsRequest);

                for (Record record : recordsResponse.records()) {
                    FlowFile flowFile = session.create();
                    final ByteBuffer buffer = record.data();
                    session.write(flowFile, out -> out.write(buffer.array(), buffer.arrayOffset() + buffer.position(), buffer.remaining()));

                    final Map<String, String> attrs = new HashMap<>();
                    attrs.put(AbstractKinesisRecordProcessor.AWS_KINESIS_SHARD_ID, shardId);
                    attrs.put(AbstractKinesisRecordProcessor.AWS_KINESIS_SEQUENCE_NUMBER, record.sequenceNumber());
                    attrs.put(AbstractKinesisRecordProcessor.AWS_KINESIS_PARTITION_KEY, record.partitionKey());
                    final Instant arrival = record.approximateArrivalTimestamp();
                    if (arrival != null) {
                        attrs.put(AbstractKinesisRecordProcessor.AWS_KINESIS_APPROXIMATE_ARRIVAL_TIMESTAMP,
                                formatter.format(arrival));
                    }
                    flowFile = session.putAllAttributes(flowFile, attrs);
                    session.transfer(flowFile, REL_SUCCESS);
                    updatedState.put(shardId, record.sequenceNumber());
                }
            }

            context.getStateManager().setState(updatedState, Scope.CLUSTER);
        } catch (final Exception e) {
            context.yield();
            getLogger().error("Failed to retrieve records from Kinesis", e);
        }
    }

    @Override
    protected KinesisClientBuilder createClientBuilder(final ProcessContext context) {
        return KinesisClient.builder();
    }
}
