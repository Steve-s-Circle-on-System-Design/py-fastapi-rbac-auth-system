from contextlib import asynccontextmanager

from fastapi import FastAPI
from scalar_fastapi import AgentScalarConfig, get_scalar_api_reference

from app.api import router as v1_router
from app.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_tags=[
        {
            "name": "User Creation",
            "description": "Admin endpoints for creating new user accounts.",
        },
    ],
)


@app.get("/docs", include_in_schema=False)
async def scalar_html():
    return get_scalar_api_reference(
        openapi_url=app.openapi_url,
        title="Python RBAC API Reference",
        servers=[{"url": "/", "description": "Current server"}],
        default_open_all_tags=True,
        expand_all_responses=True,
        expand_all_model_sections=True,
        order_schema_properties_by="preserve",
        telemetry=False,
        agent=AgentScalarConfig(disabled=True),
    )


app.include_router(v1_router, prefix=settings.API_V1_STR)



if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)