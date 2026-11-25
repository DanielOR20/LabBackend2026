import { useCallback, useEffect, useMemo, useState } from 'react';
import { Copy, Eye, EyeOff, Lock, Pencil, Plus, Search, Trash2 } from 'lucide-react';
import { api, formatError } from '../api/client.js';
import { Alert, Modal, formatDate } from '../components/ui.jsx';

const MAX_NOTES = 50;
const CATEGORIES = ['General', 'Credenciales', 'Infraestructura', 'Finanzas', 'Legal', 'Incidentes'];
const MASK = '••••••••••••';
const EMPTY_FORM = { title: '', category: 'General', tags: '', content: '' };

const parseTags = (raw) =>
  raw
    .split(',')
    .map((t) => t.trim())
    .filter(Boolean);

export default function VaultPage() {
  const [notes, setNotes] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [search, setSearch] = useState('');
  const [category, setCategory] = useState('Todas');
  const [revealed, setRevealed] = useState(() => new Set());

  const [editor, setEditor] = useState(null); // { id|null, form }
  const [editorError, setEditorError] = useState('');
  const [saving, setSaving] = useState(false);

  const [toDelete, setToDelete] = useState(null);
  const [deleting, setDeleting] = useState(false);

  const loadNotes = useCallback(async () => {
    setError('');
    try {
      const data = await api.get('/notes');
      setNotes(data.notes || []);
    } catch (err) {
      setError(formatError(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadNotes();
  }, [loadNotes]);

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    return notes.filter((note) => {
      if (category !== 'Todas' && note.category !== category) return false;
      if (!needle) return true;
      return (
        note.title.toLowerCase().includes(needle) ||
        note.content.toLowerCase().includes(needle) ||
        note.tags.some((tag) => tag.toLowerCase().includes(needle))
      );
    });
  }, [notes, search, category]);

  const toggleReveal = (id) => {
    setRevealed((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const copyContent = async (note) => {
    try {
      await navigator.clipboard.writeText(note.content);
      setNotice('Contenido copiado al portapapeles.');
      setTimeout(() => setNotice(''), 2500);
    } catch {
      setError('No se pudo copiar al portapapeles.');
    }
  };

  const openCreate = () => {
    setEditorError('');
    setEditor({ id: null, form: { ...EMPTY_FORM } });
  };

  const openEdit = (note) => {
    setEditorError('');
    setEditor({
      id: note.id,
      form: {
        title: note.title,
        category: note.category,
        tags: note.tags.join(', '),
        content: note.content
      }
    });
  };

  const updateForm = (field, value) =>
    setEditor((prev) => (prev ? { ...prev, form: { ...prev.form, [field]: value } } : prev));

  const saveNote = async (event) => {
    event.preventDefault();
    if (!editor) return;
    setEditorError('');
    setSaving(true);
    const payload = {
      title: editor.form.title,
      category: editor.form.category,
      tags: parseTags(editor.form.tags),
      content: editor.form.content
    };
    try {
      if (editor.id) {
        await api.put(`/notes/${editor.id}`, payload);
        setNotice('Nota actualizada y re-cifrada correctamente.');
      } else {
        await api.post('/notes', payload);
        setNotice('Nota cifrada y almacenada correctamente.');
      }
      setEditor(null);
      await loadNotes();
      setTimeout(() => setNotice(''), 3000);
    } catch (err) {
      setEditorError(formatError(err));
    } finally {
      setSaving(false);
    }
  };

  const confirmDelete = async () => {
    if (!toDelete) return;
    setDeleting(true);
    try {
      await api.delete(`/notes/${toDelete.id}`);
      setToDelete(null);
      setNotice('Nota eliminada permanentemente.');
      await loadNotes();
      setTimeout(() => setNotice(''), 3000);
    } catch (err) {
      setError(formatError(err));
      setToDelete(null);
    } finally {
      setDeleting(false);
    }
  };

  const atLimit = notes.length >= MAX_NOTES;

  return (
    <div className="page">
      <header className="page-header">
        <div>
          <h1>Bóveda confidencial</h1>
          <p className="muted">Notas cifradas con AES-256-GCM. Solo tú puedes verlas.</p>
        </div>
        <button type="button" className="btn btn-primary" onClick={openCreate} disabled={atLimit}>
          <Plus size={16} aria-hidden="true" /> Nueva nota
        </button>
      </header>

      <div className="toolbar card">
        <label className="search">
          <Search size={16} aria-hidden="true" />
          <input
            type="search"
            placeholder="Buscar por título, etiqueta o contenido…"
            maxLength={100}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            aria-label="Buscar notas"
          />
        </label>
        <select value={category} onChange={(e) => setCategory(e.target.value)} aria-label="Filtrar por categoría">
          <option value="Todas">Todas</option>
          {CATEGORIES.map((c) => (
            <option key={c} value={c}>{c}</option>
          ))}
        </select>
        <span className={atLimit ? 'usage usage-full' : 'usage'}>
          {notes.length} / {MAX_NOTES} notas
        </span>
      </div>

      <Alert kind="error">{error}</Alert>
      <Alert kind="success">{notice}</Alert>
      {atLimit && <Alert kind="info">Alcanzaste el límite de 50 notas. Elimina alguna para crear nuevas.</Alert>}

      {loading ? (
        <p className="muted">Cargando bóveda…</p>
      ) : filtered.length === 0 ? (
        <div className="card empty">
          <Lock size={28} aria-hidden="true" />
          <p>{notes.length === 0 ? 'Aún no tienes notas. Crea la primera.' : 'No hay notas que coincidan con el filtro.'}</p>
        </div>
      ) : (
        <div className="notes-grid">
          {filtered.map((note) => {
            const visible = revealed.has(note.id);
            return (
              <article key={note.id} className="card note-card">
                <div className="note-head">
                  <h3>{note.title}</h3>
                  <span className="chip chip-cat">{note.category}</span>
                </div>
                <div className="note-tags">
                  {note.tags.map((tag) => (
                    <span key={tag} className="chip">#{tag}</span>
                  ))}
                </div>
                <pre className={visible ? 'note-preview shown' : 'note-preview'}>{visible ? note.content : MASK}</pre>
                <div className="note-meta">
                  <span className="crypto-badge">
                    <Lock size={12} aria-hidden="true" /> AES-256-GCM · Key v{note.keyVersion}
                  </span>
                  <span className="muted small">Actualizada {formatDate(note.updatedAt)}</span>
                </div>
                <div className="note-actions">
                  <button type="button" className="icon-btn" onClick={() => toggleReveal(note.id)} aria-label={visible ? 'Ocultar contenido' : 'Mostrar contenido'}>
                    {visible ? <EyeOff size={16} /> : <Eye size={16} />}
                  </button>
                  <button type="button" className="icon-btn" onClick={() => copyContent(note)} aria-label="Copiar contenido">
                    <Copy size={16} />
                  </button>
                  <button type="button" className="icon-btn" onClick={() => openEdit(note)} aria-label="Editar nota">
                    <Pencil size={16} />
                  </button>
                  <button type="button" className="icon-btn icon-danger" onClick={() => setToDelete(note)} aria-label="Eliminar nota">
                    <Trash2 size={16} />
                  </button>
                </div>
              </article>
            );
          })}
        </div>
      )}

      {editor && (
        <Modal title={editor.id ? 'Editar nota' : 'Nueva nota cifrada'} onClose={() => setEditor(null)}>
          <form onSubmit={saveNote} className="form">
            <Alert kind="error">{editorError}</Alert>
            <label className="field">
              <span>Título</span>
              <input type="text" required maxLength={150} value={editor.form.title} onChange={(e) => updateForm('title', e.target.value)} />
            </label>
            <label className="field">
              <span>Categoría</span>
              <select value={editor.form.category} onChange={(e) => updateForm('category', e.target.value)}>
                {CATEGORIES.map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            </label>
            <label className="field">
              <span>Etiquetas (separadas por coma, máx. 10)</span>
              <input type="text" value={editor.form.tags} onChange={(e) => updateForm('tags', e.target.value)} placeholder="prod, ssh, finanzas-q4" />
            </label>
            <label className="field">
              <span>Contenido secreto ({editor.form.content.length} / 10,000)</span>
              <textarea required rows={8} maxLength={10000} value={editor.form.content} onChange={(e) => updateForm('content', e.target.value)} />
            </label>
            <div className="modal-actions">
              <button type="button" className="btn btn-ghost" onClick={() => setEditor(null)}>Cancelar</button>
              <button type="submit" className="btn btn-primary" disabled={saving}>
                {saving ? 'Cifrando…' : 'Guardar nota'}
              </button>
            </div>
          </form>
        </Modal>
      )}

      {toDelete && (
        <Modal title="Eliminar nota" size="sm" onClose={() => setToDelete(null)}>
          <p>
            ¿Eliminar permanentemente la nota <strong>{toDelete.title}</strong>? Esta acción no se puede deshacer.
          </p>
          <div className="modal-actions">
            <button type="button" className="btn btn-ghost" onClick={() => setToDelete(null)}>Cancelar</button>
            <button type="button" className="btn btn-danger" onClick={confirmDelete} disabled={deleting}>
              {deleting ? 'Eliminando…' : 'Eliminar'}
            </button>
          </div>
        </Modal>
      )}
    </div>
  );
}
