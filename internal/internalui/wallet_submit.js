// Sends the signing request to the web wallet as soon as the page has loaded (PACT §9.1). The form
// is the page's own and carries no data this script adds; without the script, its button does it.
document.getElementById("wallet-form").submit();
