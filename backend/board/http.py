"""Bounded public GETs and a separate explicitly authorized publication action."""
import re

import rfc8785
from fastapi import FastAPI, Request
from fastapi.responses import Response
from starlette.concurrency import run_in_threadpool

from backend.crypto.credential_protocol import uuid_string, strict_json
from backend.ra.demo_launcher import LocalDemoMiddleware
from backend.board.verification import BoardError, receipt_hash


def response(value,status=200):
    return Response(rfc8785.dumps(value),status_code=status,media_type="application/json")


def identifier(value):
    try: uuid_string(value);return value
    except Exception: raise BoardError(422,"INVALID_REQUEST") from None


def base():
    app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
    app.add_middleware(LocalDemoMiddleware)
    @app.middleware("http")
    async def boundary(request,call_next):
        try: result=await call_next(request)
        except Exception: result=response({"code":"UNAVAILABLE","detail":"Published evidence unavailable"},503)
        result.headers.update({"Cache-Control":"no-store","X-Content-Type-Options":"nosniff","Referrer-Policy":"no-referrer"})
        return result
    return app


def error_response(error):
    return response({"code":error.code,"detail":"Published evidence unavailable"},error.status)


def create_publication_app(service=None):
    app=base()
    @app.post("/api/v1/publication/elections/{election}/publish")
    async def publish(election:str,request:Request):
        try:
            identifier(election)
            if request.url.query or request.headers.get("content-type","").split(";")[0]!="application/json": raise BoardError(422,"INVALID_REQUEST")
            raw=bytearray()
            async for part in request.stream():
                raw.extend(part)
                if len(raw)>128: raise BoardError(413,"INVALID_REQUEST")
            if strict_json(bytes(raw))!={}: raise BoardError(422,"INVALID_REQUEST")
            headers=request.headers.getlist("authorization")
            if len(headers)!=1 or not headers[0].startswith("Bearer ") or headers[0].count(" ")!=1: raise BoardError(401,"AUTHENTICATION")
            if service is None: raise BoardError()
            return response(await run_in_threadpool(service.publish,headers[0][7:],election))
        except BoardError as error:return error_response(error)
        except (ValueError,TypeError):return error_response(BoardError(422,"INVALID_REQUEST"))
        except Exception:return error_response(BoardError())
    return app


def page(request,maximum):
    pairs=request.query_params.multi_items()
    if len(pairs)!=len(dict(pairs)) or set(dict(pairs))-{"limit","cursor"}: raise BoardError(422,"INVALID_REQUEST")
    text=request.query_params.get("limit","25")
    if re.fullmatch(r"[1-9][0-9]{0,2}",text) is None or int(text)>maximum: raise BoardError(422,"INVALID_REQUEST")
    return int(text),request.query_params.get("cursor")


def create_board_app(service=None):
    app=base()
    def dispatch(path,request):
        if service is None: raise BoardError()
        if request.headers.get('content-length','0')!='0' or 'transfer-encoding' in request.headers:raise BoardError(400,"INVALID_REQUEST")
        if any(name in request.headers for name in ("authorization","cookie","proxy-authorization","x-voter-id","x-ra-token","x-request-id","x-username","x-admin-token","x-admin-id","x-tally-token")):
            raise BoardError(400,"ANONYMOUS_REQUIRED")
        if not path:
            limit,cursor=page(request,50)
            if cursor is not None: identifier(cursor)
            return service.catalogue(cursor,limit)
        parts=path.split("/");election=identifier(parts[0])
        tail=parts[1:]
        if tail==["ballots"]:
            limit,cursor=page(request,100)
            if cursor is not None:
                fields=cursor.split(".")
                if len(fields)!=4 or fields[:2]!=["1",election]: raise BoardError(422,"INVALID_REQUEST")
                receipt_hash(fields[2]);receipt_hash(fields[3])
        elif request.url.query: raise BoardError(422,"INVALID_REQUEST")
        if len(tail)==2 and tail[0]=="receipts": receipt_hash(tail[1])
        elif tail not in (["ballots"],["evidence"],["results"],["configuration"],["snapshots","final"],["snapshots","final","manifest"]):
            raise BoardError(404,"NOT_FOUND")
        bundle=service.evidence(election)
        rows=bundle["snapshot"]["ballots"]
        if parts[1:]==["evidence"]: return bundle
        if parts[1:]==["results"]: return {"status":"PUBLISHED","election_id":election,"tally":bundle["tally"],"publication":bundle["publication"]}
        if parts[1:]==["snapshots","final"]: return bundle["snapshot"]
        if parts[1:]==["snapshots","final","manifest"]: return bundle["snapshot_evidence"]
        if parts[1:]==["configuration"]: return bundle["configuration"]
        if parts[1:]==["ballots"]:
            after=""
            if cursor is not None:
                fields=cursor.split(".")
                if len(fields)!=4 or fields[:3]!=["1",election,bundle["tally"]["report"]["snapshot_digest"]]: raise BoardError(422,"INVALID_REQUEST")
                after=receipt_hash(fields[3])
                if after not in {r["receipt_hash"] for r in rows}: raise BoardError(422,"INVALID_REQUEST")
            available=[r for r in rows if r["receipt_hash"]>after];selected=available[:limit]
            next_cursor="1."+election+"."+bundle["tally"]["report"]["snapshot_digest"]+"."+selected[-1]["receipt_hash"] if len(available)>limit else None
            return {"election_id":election,"records":selected,"next_cursor":next_cursor}
        if len(parts)==3 and parts[1]=="receipts":
            wanted=receipt_hash(parts[2])
            for record in rows:
                if record["receipt_hash"]==wanted:return {"status":"FOUND","election_id":election,"record":record}
            raise BoardError(404,"NOT_FOUND")
        raise BoardError(404,"NOT_FOUND")
    @app.get("/api/v1/board")
    @app.get("/api/v1/board/{path:path}")
    async def get(request:Request,path:str=""):
        try:return response(await run_in_threadpool(dispatch,path,request))
        except BoardError as error:return error_response(error)
        except Exception:return error_response(BoardError())
    return app
