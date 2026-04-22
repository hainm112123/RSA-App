function copyText(id) {
  const node = document.getElementById(id);
  if (!node) {
    return;
  }

  navigator.clipboard.writeText(node.textContent || node.value || "");
}
