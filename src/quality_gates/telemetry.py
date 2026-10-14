import json

from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor, SpanExporter, SpanExportResult


class Exporter(SpanExporter):
    def __init__(self, path):
        self.handle = path.open("x", encoding="utf-8")

    def export(self, spans):
        for span in spans:
            self.handle.write(
                json.dumps(
                    {
                        "name": span.name,
                        "trace_id": format(span.context.trace_id, "032x"),
                        "span_id": format(span.context.span_id, "016x"),
                        "parent_span_id": format(span.parent.span_id, "016x")
                        if span.parent
                        else None,
                        "start_ns": span.start_time,
                        "end_ns": span.end_time,
                        "attributes": dict(span.attributes),
                    }
                )
                + "\n"
            )
        self.handle.flush()
        return SpanExportResult.SUCCESS

    def shutdown(self):
        self.handle.close()


def provider(path):
    result = TracerProvider(resource=Resource.create({"service.name": "ai-native-cicd-gates"}))
    result.add_span_processor(SimpleSpanProcessor(Exporter(path)))
    return result
