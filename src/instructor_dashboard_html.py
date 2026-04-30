"""Static HTML for the instructor dashboard served at GET /.

Kept in its own module so the (already large) api_server.py doesn't grow
further. The dashboard is a single-page app: a course picker at the top
plus a registry-driven grid of service buttons. Each button reveals an
inline form built from the registry; submission goes to the corresponding
existing endpoint (session cookie carries auth). Streaming endpoints
render ndjson progress lines into an output panel.
"""

DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AI-TA Instructor Dashboard</title>
<style>
:root {
  --bg: #f6f7f9;
  --panel: #ffffff;
  --border: #d8dde3;
  --text: #1f2328;
  --muted: #57606a;
  --accent: #0969da;
  --accent-hover: #0860c2;
  --success: #1a7f37;
  --error: #cf222e;
  --warn: #9a6700;
}
* { box-sizing: border-box; }
body {
  margin: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  background: var(--bg); color: var(--text); font-size: 14px;
}
header {
  background: var(--panel); border-bottom: 1px solid var(--border);
  padding: 12px 24px; display: flex; align-items: center; gap: 24px;
  position: sticky; top: 0; z-index: 10;
}
header h1 { font-size: 18px; margin: 0; }
header .spacer { flex: 1; }
header .user { color: var(--muted); font-size: 13px; }
header a { color: var(--muted); font-size: 13px; text-decoration: none; }
header a:hover { color: var(--accent); }
main { padding: 20px 24px; max-width: 1100px; margin: 0 auto; }
.course-picker {
  background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
  padding: 16px; margin-bottom: 20px;
}
.course-picker label { display: block; font-weight: 600; margin-bottom: 6px; }
.course-picker select { width: 100%; padding: 8px; border-radius: 6px; border: 1px solid var(--border); font-size: 14px; }
.course-picker .hint { color: var(--muted); font-size: 12px; margin-top: 6px; }
.section {
  background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
  padding: 16px; margin-bottom: 16px;
}
.section h2 { font-size: 13px; margin: 0 0 10px 0; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }
.button-row { display: flex; flex-wrap: wrap; gap: 8px; }
.svc-btn {
  background: var(--panel); border: 1px solid var(--border); color: var(--text);
  padding: 8px 14px; border-radius: 6px; cursor: pointer; font-size: 13px;
}
.svc-btn:hover { border-color: var(--accent); color: var(--accent); }
.svc-btn.active { background: var(--accent); color: white; border-color: var(--accent); }
.svc-btn:disabled { opacity: 0.5; cursor: not-allowed; }
.form-panel {
  display: none; margin-top: 12px; padding: 14px;
  background: #f6f8fa; border: 1px solid var(--border); border-radius: 6px;
}
.form-panel.open { display: block; }
.form-panel .desc { color: var(--muted); font-size: 12px; margin-bottom: 8px; }
.form-panel label { display: block; margin: 8px 0 4px; font-weight: 600; font-size: 13px; }
.form-panel input[type=text], .form-panel input[type=number], .form-panel select, .form-panel textarea {
  width: 100%; padding: 7px 9px; border: 1px solid var(--border); border-radius: 5px;
  font-size: 13px; font-family: inherit;
}
.form-panel input[type=file] { font-size: 13px; margin-top: 4px; }
.form-panel textarea { min-height: 80px; resize: vertical; font-family: ui-monospace, monospace; }
.form-panel .row { display: flex; gap: 12px; }
.form-panel .row > div { flex: 1; }
.form-panel button[type=submit] {
  background: var(--accent); color: white; border: none; padding: 8px 16px;
  border-radius: 5px; cursor: pointer; font-size: 13px; margin-top: 12px;
}
.form-panel button[type=submit]:hover { background: var(--accent-hover); }
.form-panel button[type=submit]:disabled { opacity: 0.5; cursor: progress; }
.output {
  margin-top: 12px; padding: 10px; background: #ffffff; border: 1px solid var(--border);
  border-radius: 5px; font-family: ui-monospace, monospace; font-size: 12px;
  max-height: 320px; overflow-y: auto; white-space: pre-wrap; word-break: break-word;
}
.output:empty { display: none; }
.output .ok { color: var(--success); }
.output .err { color: var(--error); }
.output .warn { color: var(--warn); }
.empty {
  text-align: center; color: var(--muted); padding: 40px 20px;
}
.empty a { color: var(--accent); }
.empty code { background: #eef0f3; padding: 2px 6px; border-radius: 3px; }
</style>
</head>
<body>
<header>
  <h1>AI-TA Instructor Dashboard</h1>
  <div class="spacer"></div>
  <span class="user" id="user-info"></span>
  <a href="/docs">API docs</a>
  <a href="/logout">Sign out</a>
</header>

<main>
  <div class="course-picker">
    <label for="course-select">Course</label>
    <select id="course-select">
      <option value="">Loading…</option>
    </select>
    <div class="hint" id="course-hint">Select a course to enable the actions below.</div>
  </div>

  <div id="dashboard-body">
    <div class="empty">
      Forms will appear here once a course is selected.
      <br><br>
      Don't see your course? Make sure your email is set as
      <code>instructor_email</code>, <code>instructor_gmail</code>,
      <code>ta_email</code>, or <code>ta_gmail</code> on the course document
      in Firestore.
    </div>
  </div>
</main>

<script>
// --------------------------------------------------------------------------
// Service registry — declarative description of every form on the dashboard.
// Each entry produces one button + one form panel. The registry owns the
// label, the section, the input fields, and how to submit.
// --------------------------------------------------------------------------
const SERVICES = [
  // --- Rubric -------------------------------------------------------------
  {
    id: 'rubric_pdf_file',
    section: 'Rubric',
    label: 'Upload PDF rubric (file)',
    desc: 'Holistic PDF rubric. Stored on GCS and shown to the scoring agent as a multimodal Part alongside each student submission.',
    method: 'POST', url: '/upload_rubric_file', encoding: 'multipart',
    fields: [
      {name: 'notebook_id', label: 'Notebook / assignment ID', type: 'text', required: true},
      {name: 'max_marks', label: 'Max marks', type: 'number', step: '0.1', required: true},
      {name: 'assignment_type', type: 'hidden', value: 'pdf'},
      {name: 'file', label: 'Rubric PDF', type: 'file', accept: 'application/pdf', required: true},
    ],
  },
  {
    id: 'rubric_pdf_link',
    section: 'Rubric',
    label: 'Upload PDF rubric (Drive link)',
    desc: 'Same as above but fetches the rubric from a shared Drive link instead of a file upload.',
    method: 'POST', url: '/upload_rubric_link', encoding: 'json',
    fields: [
      {name: 'notebook_id', label: 'Notebook / assignment ID', type: 'text', required: true},
      {name: 'max_marks', label: 'Max marks', type: 'number', step: '0.1', required: true},
      {name: 'assignment_type', type: 'hidden', value: 'pdf'},
      {name: 'drive_share_link', label: 'Drive share link to rubric PDF', type: 'text', required: true,
       hint: 'The file must be shared (Viewer) with the platform service account.'},
    ],
  },
  {
    id: 'rubric_notebook_link',
    section: 'Rubric',
    label: 'Notebook rubric — use Colab client',
    desc: 'Server-side .ipynb cell parsing is not yet supported on the dashboard. Use the Colab client function ta.upload_rubric() — it parses cells locally and posts to /upload_rubric. (This button just shows this hint.)',
    method: null, // info-only
    fields: [],
  },

  // --- Course roster ------------------------------------------------------
  {
    id: 'upload_roster',
    section: 'Course roster',
    label: 'Upload student roster (CSV)',
    desc: 'Upload a CSV with columns name, email, and optional roll_no. Pre-populates Students/{email} so PDFs that only carry student names are matched to the right enrolled student during ingest. Re-uploading is safe — existing records keep their state; name/roll_no get refreshed.',
    method: 'POST', url: '/upload_student_roster', encoding: 'multipart',
    fields: [
      {name: 'file', label: 'Roster CSV', type: 'file', accept: '.csv,text/csv', required: true,
       hint: 'First row is headers. Aliases accepted: student_name / student_email / gmail / roll / student_id.'},
    ],
  },

  // --- PDF Submissions (intake only) -------------------------------------
  {
    id: 'debug_drive_access',
    section: 'PDF submissions',
    label: 'Test Drive folder/file access',
    desc: 'Diagnose whether the platform service account can read a Drive URL before running an ingest. Returns the underlying Drive API status + reason on failure (e.g. 403 insufficientFilePermissions) plus the SA email you need to share with.',
    method: 'POST', url: '/debug_drive_access', encoding: 'json',
    fields: [
      {name: 'drive_url', label: 'Drive folder or file URL', type: 'text', required: true,
       hint: 'Folder URL (.../drive/folders/<id>) or file share link (.../file/d/<id>).'},
    ],
  },
  {
    id: 'debug_pdf_authors',
    section: 'PDF submissions',
    label: 'Diagnose PDF author extraction',
    desc: 'Run the same author-extraction pipeline ingest uses (pypdf + Gemini) on a single Drive PDF. Returns the extracted text size + sample, the raw LLM response, and per-author roster matches — useful when ingest assigned a submission to a placeholder instead of the real students.',
    method: 'POST', url: '/debug_pdf_authors', encoding: 'json',
    fields: [
      {name: 'drive_url', label: 'Drive file URL (a single PDF)', type: 'text', required: true,
       hint: 'A file share link, e.g. https://drive.google.com/file/d/<id>/view'},
    ],
  },
  {
    id: 'upload_pdf_one',
    section: 'PDF submissions',
    label: 'Upload one PDF (manual attribution)',
    desc: 'Upload a single PDF directly and assign it to one or more student emails. Useful when Drive sharing is fiddly or the cover page format defeats author extraction. Auto-enrols emails that aren\'t on the course yet. Re-uploading the same PDF is idempotent (overwrites the same tracking doc, keyed by SHA-256 of contents).',
    method: 'POST', url: '/upload_pdf_submission', encoding: 'multipart',
    fields: [
      {name: 'notebook_id', label: 'Assignment ID', type: 'text', required: true},
      {name: 'student_ids', label: 'Student emails (comma- or whitespace-separated)', type: 'textarea', required: true,
       hint: 'e.g. alice@iisc.ac.in, bob@iisc.ac.in, carol@iisc.ac.in'},
      {name: 'file', label: 'PDF file', type: 'file', accept: 'application/pdf', required: true},
    ],
  },
  {
    id: 'pdf_ingest',
    section: 'PDF submissions',
    label: 'Ingest PDF submissions from Drive',
    desc: 'Reads PDFs from a shared Drive folder, copies each to GCS, extracts authors, and creates submission records. Idempotent — safe to re-run.',
    method: 'POST', url: '/ingest_pdf_submissions', encoding: 'json',
    fields: [
      {name: 'notebook_id', label: 'Assignment ID', type: 'text', required: true},
      {name: 'drive_folder_url', label: 'Drive folder URL', type: 'text', required: true,
       hint: 'Folder must be shared (Viewer) with the platform service account.'},
    ],
  },

  // --- Grading -----------------------------------------------------------
  {
    id: 'grade_assignment',
    section: 'Grading',
    label: 'Grade assignment',
    desc: 'Run the scoring agent on every submission for an assignment. Works for both PDF and Colab assignments — the server dispatches based on the rubric type. Streams progress.',
    method: 'POST', url: '/grade_assignment', encoding: 'json', streaming: true,
    fields: [
      {name: 'notebook_id', label: 'Assignment ID', type: 'text', required: true},
      {name: 'student_id', label: 'Student email or "All" (Colab assignments only — ignored for PDF)', type: 'text', value: 'All'},
      {name: 'do_regrade', label: 'Re-grade already-graded submissions', type: 'checkbox'},
    ],
  },
  {
    id: 'reassign_pdf',
    section: 'Grading',
    label: 'Re-attribute PDF submission',
    desc: 'Move a graded PDF submission off whatever student_ids ingest assigned it to (often a @pending.local placeholder when author extraction failed) and onto the right student emails. The grade is preserved — no regrade. Auto-enrols any student email that isn\'t already on the course.',
    method: 'POST', url: '/reassign_pdf_submission', encoding: 'json',
    fields: [
      {name: 'notebook_id', label: 'Assignment ID', type: 'text', required: true},
      {name: 'drive_file_id', label: 'Drive file ID', type: 'text', required: true,
       hint: 'The id from the Drive folder listing (or from the ingest summary). Not the URL.'},
      {name: 'student_ids', label: 'Student emails (comma- or whitespace-separated)', type: 'textarea', required: true,
       splitList: true,
       hint: 'e.g. alice@iisc.ac.in, bob@iisc.ac.in'},
    ],
  },
  {
    id: 'pdf_regrade_one',
    section: 'Grading',
    label: 'Regrade one PDF submission',
    desc: 'Re-grade a single student\'s PDF, optionally including their contention text.',
    method: 'POST', url: '/regrade_pdf_submission', encoding: 'json',
    fields: [
      {name: 'notebook_id', label: 'Assignment ID', type: 'text', required: true},
      {name: 'student_id', label: 'Student email', type: 'text', required: true},
      {name: 'student_contends', label: 'Student contention (optional)', type: 'textarea'},
      {name: 'do_regrade', label: 'Allow regrading even if already graded', type: 'checkbox', value: true},
    ],
  },
  {
    id: 'nb_regrade_q',
    section: 'Grading',
    label: 'Regrade one question (Colab)',
    desc: 'Re-grade a single question for one student in a Colab notebook assignment, optionally including contention.',
    method: 'POST', url: '/regrade_answer', encoding: 'json',
    fields: [
      {name: 'notebook_id', label: 'Assignment ID', type: 'text', required: true},
      {name: 'qnum', label: 'Question number', type: 'number', step: '1', required: true},
      {name: 'student_id', label: 'Student email', type: 'text', required: true},
      {name: 'student_contends', label: 'Student contention (optional)', type: 'textarea'},
      {name: 'do_regrade', label: 'Allow regrading even if already graded', type: 'checkbox', value: true},
    ],
  },

  // --- Course materials (PDFs, slides, etc.) ------------------------------
  {
    id: 'course_materials',
    section: 'Course materials',
    label: 'Upload course materials (drag-and-drop)',
    desc: 'Open the dedicated drag-and-drop page for uploading PDFs / slides to this course\'s GCS folder. After uploading, run "Build RAG index" to make the materials retrievable by the agents.',
    method: 'link', url: '/upload_course_materials',
    fields: [],
  },

  // --- Grades -------------------------------------------------------------
  {
    id: 'marks_list',
    section: 'Grades',
    label: 'Marks list',
    desc: 'List total_marks for every student on a notebook.',
    method: 'POST', url: '/fetch_marks_list', encoding: 'json',
    fields: [{name: 'notebook_id', label: 'Notebook / assignment ID', type: 'text', required: true}],
  },
  {
    id: 'grader_response',
    section: 'Grades',
    label: 'Grader response (per student)',
    desc: 'Fetch the detailed grading feedback for one student.',
    method: 'POST', url: '/fetch_grader_response', encoding: 'json',
    fields: [
      {name: 'notebook_id', label: 'Notebook / assignment ID', type: 'text', required: true},
      {name: 'student_id', label: 'Student email', type: 'text', required: true},
    ],
  },
  {
    id: 'notify_grades',
    section: 'Grades',
    label: 'Email grades to students',
    desc: 'Send each student their grade by email. "All" or one specific student. Streams progress.',
    method: 'POST', url: '/notify_student_grades', encoding: 'json', streaming: true,
    fields: [
      {name: 'notebook_id', label: 'Assignment ID', type: 'text', required: true},
      {name: 'student_id', label: 'Student email or "All"', type: 'text', required: true, value: 'All'},
      {name: 'do_resend', label: 'Resend even if already notified', type: 'checkbox'},
    ],
  },
  {
    id: 'download_marks',
    section: 'Grades',
    label: 'Download marks (CSV)',
    desc: 'Download a CSV with one row per student: student_id, name, total_marks, max_marks.',
    method: 'GET', url: '/download_marks', encoding: 'download',
    downloadFilename: (vals) => `marks_${vals.notebook_id || 'assignment'}.csv`,
    fields: [
      {name: 'notebook_id', label: 'Assignment ID', type: 'text', required: true},
      {name: 'student_id', label: 'Student email or "All"', type: 'text', required: true, value: 'All'},
    ],
  },
  {
    id: 'download_grader_response',
    section: 'Grades',
    label: 'Download grader response (JSON)',
    desc: 'Download a JSON file keyed by student email, with name, total_marks, max_marks, and the full grader_response for each.',
    method: 'GET', url: '/download_grader_response', encoding: 'download',
    downloadFilename: (vals) => `grader_response_${vals.notebook_id || 'assignment'}.json`,
    fields: [
      {name: 'notebook_id', label: 'Assignment ID', type: 'text', required: true},
      {name: 'student_id', label: 'Student email or "All"', type: 'text', required: true, value: 'All'},
    ],
  },

  // --- Course config ------------------------------------------------------
  {
    id: 'tutor_enable',
    section: 'Course config',
    label: 'Enable tutor (/assist)',
    method: 'POST', url: '/enable_tutor', encoding: 'json',
    fields: [],
  },
  {
    id: 'tutor_disable',
    section: 'Course config',
    label: 'Disable tutor (/assist)',
    method: 'POST', url: '/disable_tutor', encoding: 'json',
    fields: [],
  },
  {
    id: 'eval_enable',
    section: 'Course config',
    label: 'Enable eval (per assignment)',
    desc: 'Allow students to submit this assignment for grading. Works for both Colab and PDF assignments.',
    method: 'POST', url: '/enable_eval', encoding: 'json',
    fields: [{name: 'notebook_id', label: 'Assignment ID', type: 'text', required: true}],
  },
  {
    id: 'eval_disable',
    section: 'Course config',
    label: 'Disable eval (per assignment)',
    method: 'POST', url: '/disable_eval', encoding: 'json',
    fields: [{name: 'notebook_id', label: 'Assignment ID', type: 'text', required: true}],
  },
  {
    id: 'rate_limit_status',
    section: 'Course config',
    label: 'Rate-limit status',
    method: 'POST', url: '/rate_limit_status', encoding: 'json',
    fields: [],
  },
  // --- Agent prompts ------------------------------------------------------
  {
    id: 'view_course_prompt',
    section: 'Agent prompts',
    label: 'View agent prompt',
    desc: 'Show the prompt this course currently uses for one agent. Returns the effective override (if any) plus the default template — useful before deciding to override.',
    method: 'GET', url: '/course_prompt', encoding: 'query',
    fields: [
      {name: 'agent_type', label: 'Agent', type: 'select',
       options: [
         {value: 'instructor', label: 'instructor — content review / question creation'},
         {value: 'student', label: 'student — interactive tutor'},
         {value: 'scoring_qa', label: 'scoring_qa — per-question grading (Colab)'},
         {value: 'scoring_report', label: 'scoring_report — holistic PDF report grading'},
       ]},
    ],
  },
  {
    id: 'update_course_prompt',
    section: 'Agent prompts',
    label: 'Update agent prompt',
    desc: 'Override the default prompt for one agent on this course. Leave the textarea empty to clear the override and fall back to the default. You can use the placeholders <<course_name>> and <<course_topics>> in your prompt — they get filled in at runtime.',
    method: 'POST', url: '/update_course_prompt', encoding: 'json',
    fields: [
      {name: 'agent_type', label: 'Agent', type: 'select',
       options: [
         {value: 'instructor', label: 'instructor'},
         {value: 'student', label: 'student'},
         {value: 'scoring_qa', label: 'scoring_qa'},
         {value: 'scoring_report', label: 'scoring_report'},
       ]},
      {name: 'prompt', label: 'Prompt text (empty = clear override / use default)', type: 'textarea',
       hint: 'Tip: copy the default template from "View agent prompt" first, edit the parts you want to change, then paste back here.'},
    ],
  },

  {
    id: 'update_course_config',
    section: 'Course config',
    label: 'Update course config',
    desc: 'Change AI model, course metadata (name + topics — feed into agent prompts via <<course_name>>/<<course_topics>> placeholders), tutor toggle, or per-student rate limits. Leave any field blank to leave it unchanged.',
    method: 'POST', url: '/update_course_config', encoding: 'json',
    fields: [
      {name: 'course_name', label: 'Course name (filled into agent prompts)', type: 'text',
       hint: 'e.g. "Embedded Systems Design (E1-254)"'},
      {name: 'course_topics', label: 'Course topics (filled into agent prompts)', type: 'textarea',
       hint: 'A short paragraph the agents can reason about — what the course covers, key concepts, languages/tools.'},
      {name: 'model', label: 'AI model (e.g. gemini-2.5-pro)', type: 'text'},
      {name: 'isactive_tutor', label: 'Tutor active?', type: 'select',
       options: [{value: '', label: '— no change —'}, {value: 'true', label: 'true'}, {value: 'false', label: 'false'}]},
      {name: 'student_rate_limit', label: 'Per-student rate limit (0 to disable)', type: 'number'},
      {name: 'student_rate_limit_window', label: 'Rate-limit window (seconds, 60–86400)', type: 'number'},
    ],
  },
  {
    id: 'build_rag',
    section: 'Course config',
    label: 'Build RAG index',
    desc: 'Re-index all PDFs in the course materials folder for retrieval.',
    method: 'POST', url: '/build_course_index', encoding: 'json',
    fields: [],
  },
  {
    id: 'list_course_files',
    section: 'Course config',
    label: 'List course files (GCS)',
    method: 'POST', url: '/list_course_files', encoding: 'json',
    fields: [],
  },
];

// --------------------------------------------------------------------------
// State
// --------------------------------------------------------------------------
const state = { course: null, courses: [], openServiceId: null };

// --------------------------------------------------------------------------
// User + course bootstrap
// --------------------------------------------------------------------------
async function loadUser() {
  try {
    const r = await fetch('/whoami');
    if (r.ok) {
      const u = await r.json();
      document.getElementById('user-info').textContent = u.name || u.email || '';
    }
  } catch {}
}

async function loadCourses() {
  const sel = document.getElementById('course-select');
  const hint = document.getElementById('course-hint');
  try {
    const r = await fetch('/my_courses');
    if (!r.ok) {
      sel.innerHTML = '<option value="">Not authenticated</option>';
      return;
    }
    const data = await r.json();
    state.courses = data.courses;
    if (data.courses.length === 0) {
      sel.innerHTML = '<option value="">No courses found</option>';
      hint.textContent = 'You are not listed as instructor or TA on any course.';
      return;
    }
    sel.innerHTML = '<option value="">— select a course —</option>';
    for (const c of data.courses) {
      const label = `${c.course_id || '?'} (${c.term_id || '?'}, ${c.institution_id || '?'}) [${c.role}]`;
      sel.innerHTML += `<option value="${c.course_handle}">${escapeHtml(label)}</option>`;
    }
    hint.textContent = '';
  } catch (e) {
    sel.innerHTML = '<option value="">Error</option>';
    hint.textContent = 'Failed to load courses: ' + e.message;
  }
}

document.getElementById('course-select').addEventListener('change', (e) => {
  const handle = e.target.value;
  state.course = state.courses.find(c => c.course_handle === handle) || null;
  state.openServiceId = null;
  renderDashboard();
});

// --------------------------------------------------------------------------
// Rendering — service grid + per-form panels
// --------------------------------------------------------------------------
function renderDashboard() {
  const body = document.getElementById('dashboard-body');
  if (!state.course) {
    body.innerHTML = '<div class="empty">Forms will appear here once a course is selected.</div>';
    return;
  }

  // Group services by section
  const sections = new Map();
  for (const svc of SERVICES) {
    if (!sections.has(svc.section)) sections.set(svc.section, []);
    sections.get(svc.section).push(svc);
  }

  let html = '';
  html += `<div class="section"><h2>Selected course</h2>
    <p><strong>${escapeHtml(state.course.course_id || '?')}</strong>
       — ${escapeHtml(state.course.term_id || '?')} @ ${escapeHtml(state.course.institution_id || '?')}
       (role: ${escapeHtml(state.course.role)})</p></div>`;

  for (const [section, svcs] of sections) {
    html += `<div class="section"><h2>${escapeHtml(section)}</h2><div class="button-row">`;
    for (const svc of svcs) {
      const cls = (state.openServiceId === svc.id) ? 'svc-btn active' : 'svc-btn';
      html += `<button class="${cls}" data-svc="${svc.id}">${escapeHtml(svc.label)}</button>`;
    }
    html += `</div>`;
    if (state.openServiceId) {
      const svc = svcs.find(s => s.id === state.openServiceId);
      if (svc) html += renderForm(svc);
    }
    html += `</div>`;
  }
  body.innerHTML = html;

  for (const btn of body.querySelectorAll('.svc-btn')) {
    btn.addEventListener('click', () => {
      state.openServiceId = (state.openServiceId === btn.dataset.svc) ? null : btn.dataset.svc;
      renderDashboard();
    });
  }
  for (const f of body.querySelectorAll('form[data-svc]')) {
    f.addEventListener('submit', onSubmit);
  }
}

function renderForm(svc) {
  if (svc.method === null) {
    return `<div class="form-panel open"><div class="desc">${escapeHtml(svc.desc || '')}</div></div>`;
  }
  if (svc.method === 'link') {
    // Plain navigation. Open in a new tab so the dashboard state is preserved.
    return `<div class="form-panel open">
      <div class="desc">${escapeHtml(svc.desc || '')}</div>
      <a href="${escapeAttr(svc.url)}" target="_blank" rel="noopener"
         style="display:inline-block;background:var(--accent);color:white;padding:8px 16px;border-radius:5px;text-decoration:none;font-size:13px;margin-top:8px;">
         Open in new tab →
      </a>
    </div>`;
  }
  let html = `<div class="form-panel open"><form data-svc="${svc.id}">`;
  if (svc.desc) html += `<div class="desc">${escapeHtml(svc.desc)}</div>`;
  for (const f of svc.fields) {
    if (f.type === 'hidden') {
      html += `<input type="hidden" name="${f.name}" value="${escapeAttr(f.value || '')}">`;
      continue;
    }
    html += `<label>${escapeHtml(f.label)}`;
    if (f.required) html += ` <span style="color:var(--error)">*</span>`;
    html += `</label>`;
    if (f.type === 'textarea') {
      html += `<textarea name="${f.name}"></textarea>`;
    } else if (f.type === 'select') {
      html += `<select name="${f.name}">`;
      for (const opt of (f.options || [])) {
        html += `<option value="${escapeAttr(opt.value)}">${escapeHtml(opt.label)}</option>`;
      }
      html += `</select>`;
    } else if (f.type === 'checkbox') {
      html += `<input type="checkbox" name="${f.name}"${f.value ? ' checked' : ''}>`;
    } else if (f.type === 'file') {
      html += `<input type="file" name="${f.name}"${f.accept ? ` accept="${escapeAttr(f.accept)}"` : ''}${f.required ? ' required' : ''}>`;
    } else {
      const stepAttr = f.step ? ` step="${escapeAttr(f.step)}"` : '';
      const valAttr = f.value !== undefined ? ` value="${escapeAttr(f.value)}"` : '';
      html += `<input type="${f.type}" name="${f.name}"${stepAttr}${valAttr}${f.required ? ' required' : ''}>`;
    }
    if (f.hint) html += `<div class="desc" style="margin-top:4px">${escapeHtml(f.hint)}</div>`;
  }
  html += `<button type="submit">Submit</button>`;
  html += `<div class="output" id="out-${svc.id}"></div>`;
  html += `</form></div>`;
  return html;
}

// --------------------------------------------------------------------------
// Form submission — JSON or multipart, plus ndjson streaming
// --------------------------------------------------------------------------
async function onSubmit(e) {
  e.preventDefault();
  const form = e.target;
  const svcId = form.dataset.svc;
  const svc = SERVICES.find(s => s.id === svcId);
  const out = form.querySelector('.output');
  out.innerHTML = '';
  const submitBtn = form.querySelector('button[type=submit]');
  submitBtn.disabled = true;

  try {
    if (svc.encoding === 'query') {
      // GET with form values as query params; render the JSON response
      // inline (used by /course_prompt and similar read-only fetches).
      const vals = collectFieldValues(form, svc);
      const url = buildQueryUrl(svc.url, vals);
      const r = await fetch(url, { method: 'GET' });
      if (!r.ok) {
        let detail = '';
        try { detail = (await r.json()).detail || ''; } catch { detail = await r.text(); }
        appendOut(out, 'err', `HTTP ${r.status}: ${detail}`);
        return;
      }
      const data = await r.json();
      appendOut(out, 'ok', JSON.stringify(data, null, 2));
      return;
    }

    if (svc.encoding === 'download') {
      // GET request with query params; trigger a browser download via Blob.
      const vals = collectFieldValues(form, svc);
      const url = buildQueryUrl(svc.url, vals);
      const r = await fetch(url, { method: 'GET' });
      if (!r.ok) {
        let detail = '';
        try { detail = (await r.json()).detail || ''; } catch { detail = await r.text(); }
        appendOut(out, 'err', `HTTP ${r.status}: ${detail}`);
        return;
      }
      const blob = await r.blob();
      const fname = svc.downloadFilename ? svc.downloadFilename(vals) : 'download';
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = fname;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(a.href);
      appendOut(out, 'ok', `Downloaded ${fname} (${blob.size} bytes).`);
      return;
    }

    const body = svc.encoding === 'multipart'
      ? buildMultipart(form, svc)
      : buildJsonBody(form, svc);

    const headers = {};
    if (svc.encoding === 'json') headers['Content-Type'] = 'application/json';

    const fetchOpts = {
      method: svc.method,
      headers,
      body: svc.encoding === 'json' ? JSON.stringify(body) : body,
    };
    const r = await fetch(svc.url, fetchOpts);

    if (!r.ok) {
      let detail = '';
      try { detail = (await r.json()).detail || ''; } catch { detail = await r.text(); }
      appendOut(out, 'err', `HTTP ${r.status}: ${detail}`);
      return;
    }

    if (svc.streaming) {
      await renderStream(r, out);
    } else {
      const data = await r.json();
      appendOut(out, 'ok', JSON.stringify(data, null, 2));
    }
  } catch (err) {
    appendOut(out, 'err', 'Request failed: ' + err.message);
  } finally {
    submitBtn.disabled = false;
  }
}

function collectFieldValues(form, svc) {
  // Plain key-value collection for GET/download. Always includes course IDs.
  const vals = {
    institution_id: state.course.institution_id,
    term_id: state.course.term_id,
    course_id: state.course.course_id,
  };
  for (const f of svc.fields) {
    const el = form.elements[f.name];
    if (!el) continue;
    if (f.type === 'checkbox') vals[f.name] = el.checked ? 'true' : 'false';
    else if (el.value !== '') vals[f.name] = el.value;
  }
  return vals;
}

function buildQueryUrl(base, vals) {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(vals)) {
    if (v !== undefined && v !== null && v !== '') params.append(k, v);
  }
  return base + '?' + params.toString();
}

function buildJsonBody(form, svc) {
  const body = {};
  // Always inject course identifiers.
  body.institution_id = state.course.institution_id;
  body.term_id = state.course.term_id;
  body.course_id = state.course.course_id;
  for (const f of svc.fields) {
    if (f.type === 'hidden') {
      body[f.name] = f.value;
      continue;
    }
    const el = form.elements[f.name];
    if (!el) continue;
    if (f.type === 'checkbox') body[f.name] = !!el.checked;
    else if (f.type === 'number') body[f.name] = el.value === '' ? null : Number(el.value);
    else if (f.splitList && el.value !== '') {
      // Split a textarea / text input into an array on commas / whitespace.
      body[f.name] = el.value.split(/[\s,]+/).filter(Boolean);
    }
    else if (f.type === 'select') {
      const v = el.value;
      if (v === '') continue;        // — no change —
      if (v === 'true') body[f.name] = true;
      else if (v === 'false') body[f.name] = false;
      else body[f.name] = v;
    }
    else if (el.value !== '') body[f.name] = el.value;
  }
  return body;
}

function buildMultipart(form, svc) {
  const fd = new FormData();
  fd.append('institution_id', state.course.institution_id);
  fd.append('term_id', state.course.term_id);
  fd.append('course_id', state.course.course_id);
  for (const f of svc.fields) {
    if (f.type === 'hidden') {
      fd.append(f.name, f.value);
      continue;
    }
    const el = form.elements[f.name];
    if (!el) continue;
    if (f.type === 'file') {
      if (el.files[0]) fd.append(f.name, el.files[0]);
    } else if (f.type === 'checkbox') {
      fd.append(f.name, el.checked ? 'true' : 'false');
    } else if (el.value !== '') {
      fd.append(f.name, el.value);
    }
  }
  return fd;
}

async function renderStream(response, out) {
  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buf = '';
  while (true) {
    const { value, done } = await reader.read();
    if (done) break;
    buf += decoder.decode(value, { stream: true });
    let nl;
    while ((nl = buf.indexOf('\n')) !== -1) {
      const line = buf.slice(0, nl).trim();
      buf = buf.slice(nl + 1);
      if (!line) continue;
      try {
        const evt = JSON.parse(line);
        renderStreamEvent(evt, out);
      } catch {
        appendOut(out, '', line);
      }
    }
  }
  if (buf.trim()) appendOut(out, '', buf.trim());
}

function renderStreamEvent(evt, out) {
  if (evt.type === 'progress') appendOut(out, '', evt.message || JSON.stringify(evt));
  else if (evt.type === 'heartbeat') {} // suppress noise
  else if (evt.type === 'response') appendOut(out, 'ok', evt.response || JSON.stringify(evt));
  else if (evt.type === 'error') appendOut(out, 'err', evt.detail || JSON.stringify(evt));
  else appendOut(out, '', JSON.stringify(evt));
}

function appendOut(out, cls, text) {
  const span = document.createElement('div');
  if (cls) span.className = cls;
  span.textContent = text;
  out.appendChild(span);
  out.scrollTop = out.scrollHeight;
}

function escapeHtml(s) {
  return String(s ?? '')
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;');
}
function escapeAttr(s) {
  return String(s ?? '')
    .replaceAll('&', '&amp;').replaceAll('"', '&quot;');
}

loadUser();
loadCourses();
</script>
</body>
</html>
"""
