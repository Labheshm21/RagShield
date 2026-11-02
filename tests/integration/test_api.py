from ragshield.api import create_app
from ragshield.models import DocumentInput, QueryRequest, SecurityMode


def test_ingest_then_query_supported_fact() -> None:
    app = create_app(mode=SecurityMode.DEFENDED, database=":memory:")
    endpoints = {
        route.path: route.endpoint
        for route in app.routes
        if route.path in {"/documents", "/query"}
    }
    ingest = endpoints["/documents"](
        DocumentInput.model_validate({
            "document_id": "returns",
            "filename": "returns.md",
            "content": "# Returns\nFACT: Returns are accepted for 30 days.",
            "trust": "trusted",
        })
    )
    response = endpoints["/query"](
        QueryRequest(question="When are returns accepted?")
    )
    assert ingest.status == "indexed"
    assert response.answer == "Returns are accepted for 30 days."
    assert response.citations[0].document_id == "returns"

