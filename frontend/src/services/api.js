const API_BASE_URL =
  import.meta.env.VITE_API_URL ||
  "http://127.0.0.1:8000";

async function parseResponse(response) {
  if (!response.ok) {
    let data = null;

    try {
      data = await response.json();
    } catch {
      // Response was not JSON.
    }

    throw new Error(
      data?.detail ||
        `Request failed with status ${response.status}.`
    );
  }

  return response;
}

export async function uploadConfiguration(file) {
  if (!(file instanceof File)) {
    throw new Error(
      "Please select a valid configuration file."
    );
  }

  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(
    `${API_BASE_URL}/api/upload`,
    {
      method: "POST",
      body: formData,
    }
  );

  const checkedResponse =
    await parseResponse(response);

  return checkedResponse.json();
}

export async function auditConfiguration(file) {
  if (!(file instanceof File)) {
    throw new Error(
      "Please select a valid configuration file."
    );
  }

  const formData = new FormData();
  formData.append("file", file);

  const response = await fetch(
    `${API_BASE_URL}/api/audit`,
    {
      method: "POST",
      body: formData,
    }
  );

  const checkedResponse =
    await parseResponse(response);

  return checkedResponse.json();
}

export async function downloadAuditReport(
  auditResult
) {
  const response = await fetch(
    `${API_BASE_URL}/api/reports/generate`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        audit_result: auditResult,
      }),
    }
  );

  const checkedResponse =
    await parseResponse(response);

  const blob =
    await checkedResponse.blob();

  const contentDisposition =
    checkedResponse.headers.get(
      "content-disposition"
    );

  let filename =
    "network-security-audit.pdf";

  const filenameMatch =
    contentDisposition?.match(
      /filename="?([^"]+)"?/
    );

  if (filenameMatch?.[1]) {
    filename = filenameMatch[1];
  }

  const url =
    window.URL.createObjectURL(blob);

  const link =
    document.createElement("a");

  link.href = url;
  link.download = filename;

  document.body.appendChild(link);
  link.click();
  link.remove();

  window.URL.revokeObjectURL(url);
}