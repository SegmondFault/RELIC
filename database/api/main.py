from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, FastAPI, HTTPException, Query

app = FastAPI(title="RELIC API", version="0.1.0")

"""TODO: Put each router & its endpoints in separate file. See docs for endpoint details."""

def todo() -> None:
    raise HTTPException(status_code=501, detail="Not implemented yet, come back later")


@app.get("/healthz", tags=["health"])
async def healthz():
    return {"status": "ok"}

v1 = APIRouter(prefix="/v1")

auth = APIRouter(tags=["auth"])

@auth.post("/auth/login")
async def login():
    todo()

@auth.get("/me")
async def me():
    todo()


catalogue = APIRouter(tags=["catalogue"])

@catalogue.get("/users")
async def list_users(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()

@catalogue.get("/users/{user_id}")
async def get_user(user_id: UUID):
    todo()

@catalogue.get("/sources")
async def list_sources(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()

@catalogue.get("/sources/{source_id}")
async def get_source(source_id: UUID):
    todo()

@catalogue.get("/batches")
async def list_batches(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()

@catalogue.get("/batches/{batch_id}")
async def get_batch(batch_id: UUID):
    todo()

@catalogue.get("/binaries")
async def list_binaries(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()

@catalogue.get("/binaries/{binary_id}")
async def get_binary(binary_id: UUID):
    todo()

@catalogue.get("/functions")
async def list_functions(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()

@catalogue.get("/functions/{function_id}")
async def get_function(function_id: UUID):
    todo()

@catalogue.get("/fidbf")
async def list_fidbf(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()

@catalogue.get("/fidbf/{fidbf_id}")
async def get_fidbf(fidbf_id: UUID):
    todo()

@catalogue.get("/fidbf/{fidbf_id}/download")
async def download_fidbf(fidbf_id: UUID):
    todo()

@catalogue.get("/bsim")
async def list_bsim(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()

@catalogue.get("/bsim/{bsim_id}")
async def get_bsim(bsim_id: UUID):
    todo()

@catalogue.get("/function-bsim")
async def list_function_bsim(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()

@catalogue.get("/provenance")
async def list_provenance(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()

@catalogue.get("/provenance/{provenance_id}")
async def get_provenance(provenance_id: UUID):
    todo()

@catalogue.get("/license-assertions")
async def list_license_assertions(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()

@catalogue.get("/license-assertions/{license_assertion_id}")
async def get_license_assertion(license_assertion_id: UUID):
    todo()

@catalogue.get("/classifications")
async def list_classifications(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()

@catalogue.get("/classifications/{classification_id}")
async def get_classification(classification_id: UUID):
    todo()

@catalogue.get("/flags")
async def list_flags(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()

@catalogue.get("/flags/{flag_id}")
async def get_flag(flag_id: UUID):
    todo()

@catalogue.get("/flag-responses")
async def list_flag_responses(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()

@catalogue.get("/revocations")
async def list_revocations(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()

@catalogue.get("/revocations/{revocation_id}")
async def get_revocation(revocation_id: UUID):
    todo()

@catalogue.get("/integrity")
async def list_integrity(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()

@catalogue.get("/integrity/{integrity_id}")
async def get_integrity(integrity_id: int):
    todo()

@catalogue.get("/mmr-checkpoints")
async def list_mmr_checkpoints(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0)):
    todo()

@catalogue.get("/mmr-checkpoints/latest")
async def latest_mmr_checkpoint():
    todo()

@catalogue.get("/mmr-checkpoints/{mmr_checkpoint_id}")
async def get_mmr_checkpoint(mmr_checkpoint_id: int):
    todo()


submissions = APIRouter(tags=["submissions"])

@submissions.post("/sources", status_code=201)
async def submit_source():
    todo()

@submissions.post("/batches", status_code=201)
async def submit_batch():
    todo()

@submissions.post("/fidbf", status_code=201)
async def submit_fidbf():
    todo()

@submissions.post("/bsim", status_code=201)
async def submit_bsim():
    todo()

@submissions.post("/provenance", status_code=201)
async def submit_provenance():
    todo()

@submissions.post("/license-assertions", status_code=201)
async def submit_license_assertion():
    todo()

@submissions.post("/classifications", status_code=201)
async def submit_classification():
    todo()


flags = APIRouter(tags=["flags"])

@flags.post("/flags", status_code=201)
async def submit_flag():
    todo()

@flags.post("/flags/{flag_id}/responses", status_code=201)
async def respond_to_flag(flag_id: UUID):
    todo()


revocations = APIRouter(tags=["revocations"])

@revocations.post("/revocations", status_code=201)
async def request_revocation():
    todo()

@revocations.post("/revocations/{revocation_id}/decision")
async def decide_revocation(revocation_id: UUID):
    todo()


accounts = APIRouter(tags=["accounts"])

@accounts.post("/accounts", status_code=201)
async def create_account():
    todo()



for router in (auth, catalogue, submissions, flags, revocations, accounts):
    v1.include_router(router)

app.include_router(v1)