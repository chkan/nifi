package org.apache.nifi.processors.aws.kinesis.stream;

import org.apache.nifi.annotation.behavior.InputRequirement;
import org.apache.nifi.annotation.behavior.InputRequirement.Requirement;
import org.apache.nifi.annotation.behavior.Stateful;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.SeeAlso;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.components.AllowableValue;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.components.state.Scope;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.util.StandardValidators;
import org.apache.nifi.processors.aws.kinesis.stream.record.AbstractKinesisRecordProcessor;
import org.apache.nifi.processors.aws.v2.AbstractAwsSyncProcessor;
import software.amazon.awssdk.services.kinesis.KinesisClient;
import software.amazon.awssdk.services.kinesis.KinesisClientBuilder;
import software.amazon.awssdk.services.kinesis.model.GetRecordsRequest;
import software.amazon.awssdk.services.kinesis.model.GetRecordsResponse;
import software.amazon.awssdk.services.kinesis.model.GetShardIteratorRequest;
import software.amazon.awssdk.services.kinesis.model.GetShardIteratorResponse;
import software.amazon.awssdk.services.kinesis.model.ListShardsRequest;
import software.amazon.awssdk.services.kinesis.model.ListShardsResponse;
import software.amazon.awssdk.services.kinesis.model.Record;
import software.amazon.awssdk.services.kinesis.model.Shard;
import software.amazon.awssdk.services.kinesis.model.ShardIteratorType;

import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Processor that retrieves records from Kinesis using the AWS SDK without the Kinesis Client Library.
 */
@Tags({"amazon", "aws", "kinesis", "get", "stream"})
@InputRequirement(Requirement.INPUT_FORBIDDEN)
@CapabilityDescription("Retrieves records from an Amazon Kinesis stream using the AWS SDK." +
        " Checkpoints are managed using NiFi state so that the processor resumes from the last successfully" +
        " processed sequence number.")
@SeeAlso({PutKinesisStream.class, ConsumeKinesisStream.class})
@Stateful(scopes = Scope.CLUSTER, description = "Stores the last processed sequence number for each shard")
public class GetKinesisRecords extends AbstractAwsSyncProcessor<KinesisClient, KinesisClientBuilder> {

    static final AllowableValue LATEST = new AllowableValue("LATEST", "Latest", "Read from the latest data");
    static final AllowableValue TRIM_HORIZON = new AllowableValue("TRIM_HORIZON", "Trim Horizon", "Read from the oldest available data");
    static final AllowableValue AT_TIMESTAMP = new AllowableValue("AT_TIMESTAMP", "At Timestamp", "Read starting at the specified timestamp");

    static final PropertyDescriptor KINESIS_STREAM_NAME = new PropertyDescriptor.Builder()
            .name("kinesis-stream-name")
            .displayName("Amazon Kinesis Stream Name")
            .description("The name of Kinesis Stream")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    static final PropertyDescriptor INITIAL_STREAM_POSITION = new PropertyDescriptor.Builder()
            .name("Initial Stream Position")
            .description("Initial position to read Kinesis stream shards")
            .allowableValues(LATEST, TRIM_HORIZON, AT_TIMESTAMP)
            .defaultValue(LATEST.getValue())
            .required(true)
            .build();

    static final PropertyDescriptor STREAM_POSITION_TIMESTAMP = new PropertyDescriptor.Builder()
            .name("Stream Position Timestamp")
            .description("Timestamp position in stream from which to start reading records when 'At Timestamp' is selected")
            .required(false)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .dependsOn(INITIAL_STREAM_POSITION, AT_TIMESTAMP)
            .build();

    static final PropertyDescriptor BATCH_SIZE = new PropertyDescriptor.Builder()
            .name("Batch Size")
            .description("Maximum number of records to retrieve per request")
            .required(true)
            .defaultValue("1000")
            .addValidator(StandardValidators.POSITIVE_INTEGER_VALIDATOR)
            .build();

    static final List<PropertyDescriptor> PROPERTY_DESCRIPTORS = List.of(
            KINESIS_STREAM_NAME,
            INITIAL_STREAM_POSITION,
            STREAM_POSITION_TIMESTAMP,
            BATCH_SIZE,
            REGION,
            AWS_CREDENTIALS_PROVIDER_SERVICE,
            TIMEOUT,
            PROXY_CONFIGURATION_SERVICE,
            ENDPOINT_OVERRIDE
    );

    private final Map<String, String> shardIterators = new HashMap<>();
    private final Set<String> shardIds = new HashSet<>();

    @Override
    protected List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return PROPERTY_DESCRIPTORS;
    }

    @Override
    public void onScheduled(final ProcessContext context) {
        super.onScheduled(context);
        shardIterators.clear();
        shardIds.clear();

        final KinesisClient client = getClient(context);
        final String streamName = context.getProperty(KINESIS_STREAM_NAME).getValue();
        final Map<String, String> state;
        try {
            state = context.getStateManager().getState(Scope.CLUSTER).toMap();
        } catch (IOException e) {
            throw new ProcessException("Failed to obtain state", e);
        }

        final ListShardsResponse shards = client.listShards(ListShardsRequest.builder().streamName(streamName).build());
        for (Shard shard : shards.shards()) {
            shardIds.add(shard.shardId());
            final GetShardIteratorRequest.Builder iteratorRequest = GetShardIteratorRequest.builder()
                    .streamName(streamName)
                    .shardId(shard.shardId());
            final String sequence = state.get("sequence." + shard.shardId());
            if (sequence != null) {
                iteratorRequest.shardIteratorType(ShardIteratorType.AFTER_SEQUENCE_NUMBER)
                        .startingSequenceNumber(sequence);
            } else {
                final String position = context.getProperty(INITIAL_STREAM_POSITION).getValue();
                iteratorRequest.shardIteratorType(ShardIteratorType.fromValue(position));
                if (AT_TIMESTAMP.getValue().equals(position)) {
                    final String timestamp = context.getProperty(STREAM_POSITION_TIMESTAMP).getValue();
                    if (timestamp != null) {
                        Instant instant = DateTimeFormatter.ISO_DATE_TIME.parse(timestamp, Instant::from);
                        iteratorRequest.timestamp(instant);
                    }
                }
            }
            final GetShardIteratorResponse response = client.getShardIterator(iteratorRequest.build());
            shardIterators.put(shard.shardId(), response.shardIterator());
        }
    }

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
        final KinesisClient client = getClient(context);
        final int batchSize = context.getProperty(BATCH_SIZE).asInteger();
        final Map<String, String> newState = new HashMap<>();

        for (final String shardId : shardIds) {
            String iterator = shardIterators.get(shardId);
            if (iterator == null) {
                continue;
            }

            final GetRecordsResponse response = client.getRecords(GetRecordsRequest.builder()
                    .shardIterator(iterator)
                    .limit(batchSize)
                    .build());

            for (Record record : response.records()) {
                FlowFile flowFile = session.create();
                session.write(flowFile, out -> out.write(record.data().asByteArray()));
                final Map<String, String> attrs = Map.of(
                        AbstractKinesisRecordProcessor.AWS_KINESIS_SHARD_ID, shardId,
                        AbstractKinesisRecordProcessor.AWS_KINESIS_SEQUENCE_NUMBER, record.sequenceNumber(),
                        AbstractKinesisRecordProcessor.AWS_KINESIS_PARTITION_KEY, record.partitionKey(),
                        AbstractKinesisRecordProcessor.AWS_KINESIS_APPROXIMATE_ARRIVAL_TIMESTAMP, record.approximateArrivalTimestamp().toString()
                );
                flowFile = session.putAllAttributes(flowFile, attrs);
                session.transfer(flowFile, REL_SUCCESS);
                newState.put("sequence." + shardId, record.sequenceNumber());
            }

            iterator = response.nextShardIterator();
            shardIterators.put(shardId, iterator);
        }

        if (!newState.isEmpty()) {
            try {
                context.getStateManager().setState(newState, Scope.CLUSTER);
            } catch (IOException e) {
                throw new ProcessException("Failed to store state", e);
            }
        }
    }

    @Override
    protected KinesisClientBuilder createClientBuilder(final ProcessContext context) {
        return KinesisClient.builder();
    }
}
