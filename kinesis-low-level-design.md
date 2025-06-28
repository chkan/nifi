# Alternative Design: Low-Level AWS SDK for NiFi Kinesis Processors

## Background

`ConsumeKinesisStream` relies on the **Kinesis Client Library** (KCL) to manage shard
threading, state checkpoints and record retrieval.  The processor
initializes a `Scheduler` instance that internally creates worker threads and manages
checkpointing via DynamoDB.  Examples of the current approach can be seen in
`ConsumeKinesisStream.java`:

```
AWS Kinesis Client Library can take several seconds to initialise before starting to fetch data.
```
【F:nifi-extension-bundles/nifi-aws-bundle/nifi-aws-processors/src/main/java/org/apache/nifi/processors/aws/kinesis/stream/ConsumeKinesisStream.java†L124-L130】

and the worker startup logic:

```
scheduler = prepareScheduler(context, sessionFactory, schedulerId);
new Thread(scheduler, SCHEDULER_THREAD_NAME_TEMPLATE + schedulerId).start();
```
【F:nifi-extension-bundles/nifi-aws-bundle/nifi-aws-processors/src/main/java/org/apache/nifi/processors/aws/kinesis/stream/ConsumeKinesisStream.java†L606-L616】

Dynamic properties allow direct configuration of the KCL builder:

```
@DynamicProperty(name = "Kinesis Client Library (KCL) Configuration property name", ... )
```
【F:nifi-extension-bundles/nifi-aws-bundle/nifi-aws-processors/src/main/java/org/apache/nifi/processors/aws/kinesis/stream/ConsumeKinesisStream.java†L145-L155】

Using KCL hides the polling mechanism and shard control within the library.  NiFi
has limited visibility and is unable to align scheduling or checkpoints directly
with the flow.

## Proposed Approach

Implement a new processor (e.g. `GetKinesisRecords`) that uses the lower level
`KinesisClient` or `KinesisAsyncClient` APIs instead of KCL.  The processor will
explicitly poll each shard and maintain sequence checkpoints using NiFi's
`StateManager` or DynamoDB if desired.  The following features are proposed:

1. **Shard Enumeration & Iterators**
   * On schedule, list stream shards via `ListShards` and store shard IDs in
     processor state.
   * For each shard, obtain a `ShardIterator` using the configured starting
     strategy (`TRIM_HORIZON`, `LATEST`, or `AT_TIMESTAMP`).
   * Persist the last sequence number (or iterator) for each shard in state so
     that restarts continue from the correct position.

2. **Polling Loop in onTrigger**
   * `onTrigger` will iterate over tracked shards and invoke
     `GetRecords` (or the asynchronous `SubscribeToShard`) with a configurable
     max record count and wait time.
   * The NiFi scheduling period defines polling frequency, allowing back pressure
     and load management without KCL threads.
   * Retrieved records are converted to FlowFiles similarly to the existing
     `AbstractKinesisRecordProcessor` implementations.

3. **Checkpoint Handling**
   * After successful FlowFile transfer, update the sequence number for each
     shard in `StateManager`.
   * Optionally provide a DynamoDB checkpoint service for compatibility with
     existing environments.
   * Provide properties for retry count and interval when fetching or updating
     checkpoints.

4. **Record and Batch Modes**
   * Support the same Record Reader / Record Writer options already present in
     `ConsumeKinesisStream` so FlowFiles may contain individual records or
     batches.
   * Attributes such as shard ID, sequence number and approximate arrival
     timestamp are added in the same manner.

5. **NiFi‑Managed Concurrency**
   * Since there is no scheduler thread pool inside the processor, each
     `onTrigger` invocation runs within NiFi’s standard scheduling framework.
   * The number of concurrent tasks configured for the processor directly
     controls parallelism, and there are no hidden threads.

6. **Simplified Configuration**
   * Without KCL, there is no need for dynamic property injection of KCL
     configuration.  Processor properties will expose only the options relevant
     to direct Kinesis calls (stream name, iterator type, batch size, etc.).

## Benefits

* **Predictable Resource Usage** – All work happens within NiFi’s own threads,
  so administrators have full visibility into CPU and memory requirements.
* **Custom Checkpoint Strategy** – Checkpoints can be stored in NiFi state or a
  user‑supplied service, allowing tighter control over exactly-once delivery and
  easier troubleshooting.
* **Reduced Dependencies** – Eliminates the KCL and DynamoDB requirement for
  simple use cases where NiFi alone can track progress.
* **Flexible Back Pressure** – Polling frequency and batch sizes can be tuned
  directly from processor settings without interacting with KCL internals.

## High Level Class Sketch

```java
public class GetKinesisRecords extends AbstractAwsSyncProcessor<KinesisClient, KinesisClientBuilder> {
    // Properties: stream name, iterator type, timestamp, max records, etc.

    @OnScheduled
    public void onScheduled(final ProcessContext context) {
        // list shards and initialize iterators using StateManager
    }

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) {
        // for each shard -> GetRecords -> create FlowFiles -> update checkpoints
    }

    @Override
    protected KinesisClientBuilder createClientBuilder(final ProcessContext context) {
        return KinesisClient.builder();
    }
}
```

Record handling can reuse the existing `KinesisRecordProcessorRaw` and
`KinesisRecordProcessorRecord` classes with minor adjustments so that they work
without the `ShardRecordProcessor` interface.

## Migration Considerations

* Existing `ConsumeKinesisStream` remains for KCL‑based implementations that
  require its advanced failover features.
* The new processor targets simpler scenarios where NiFi developers want
  complete control over polling and checkpoints.
* Documentation should highlight differences in delivery guarantees and required
  configuration compared to the current processor.

---
