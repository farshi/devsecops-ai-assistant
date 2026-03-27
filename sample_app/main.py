from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import uuid

app = FastAPI(title="Notes API", description="Sample app for DevSecOps scanning demos")

# In-memory storage
notes: dict = {}


class NoteIn(BaseModel):
    title: str
    content: str


class Note(BaseModel):
    id: str
    title: str
    content: str


@app.get("/health")
def health():
    return {"status": "ok", "notes_count": len(notes)}


@app.get("/notes", response_model=list[Note])
def list_notes():
    return list(notes.values())


@app.get("/notes/{note_id}", response_model=Note)
def get_note(note_id: str):
    if note_id not in notes:
        raise HTTPException(status_code=404, detail="Note not found")
    return notes[note_id]


@app.post("/notes", response_model=Note, status_code=201)
def create_note(note: NoteIn):
    note_id = str(uuid.uuid4())
    new_note = {"id": note_id, "title": note.title, "content": note.content}
    notes[note_id] = new_note
    return new_note


@app.delete("/notes/{note_id}", status_code=204)
def delete_note(note_id: str):
    if note_id not in notes:
        raise HTTPException(status_code=404, detail="Note not found")
    del notes[note_id]
