CREATE TRIGGER lab_note_material_immutable
BEFORE UPDATE ON lab_note
BEGIN
    SELECT RAISE(ABORT, 'lab note material is immutable');
END;

CREATE TRIGGER lab_note_no_delete
BEFORE DELETE ON lab_note
BEGIN
    SELECT RAISE(ABORT, 'lab notes are immutable');
END;
