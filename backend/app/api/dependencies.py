from fastapi import Request

from app.repositories import SQLiteRepository


def repository(request: Request) -> SQLiteRepository:
    return request.app.state.repository


def graph(request: Request):
    return request.app.state.graph


def investigation_service(request: Request):
    return request.app.state.investigation_service
