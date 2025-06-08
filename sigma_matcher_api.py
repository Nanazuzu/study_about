from fastapi import FastAPI, Request
import json
from sigma.parser.collection import SigmaCollectionParser
from sigma.collection import SigmaCollection

app = FastAPI()

# Sigma Rule Collection 로드
parser = SigmaCollectionParser(["./sigma_rules/*.yml"])
sigma_collection = parser.parse()

@app.post("/match")
async def match_sigma(request: Request):
    data = await request.json()
    span_attributes = data.get("attributes", {})

    match_result = "no_match"

    for rule in sigma_collection.rules:
        detection = rule.detection
        if "selection" in detection.detections:
            selection_fields = detection.detections["selection"]
            field_matches = all(
                span_attributes.get(field) == value
                for field, value in selection_fields.items()
            )
            if field_matches:
                match_result = f"matched_rule: {rule.title}"
                break

    return {"sigma_match_result": match_result}
