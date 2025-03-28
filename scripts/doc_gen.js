//------------------------------------------------------------------------------
//  Copyright(C) 2025 Intel Corporation. All Rights Reserved.
// 
// This node script generates an HTML document from the reference values JSON 
// file that is included in build output.
//------------------------------------------------------------------------------
const fs = require("fs");

const args = process.argv.slice(2);
if(args.length < 1) {
    console.log("Usage: node doc_gen.js <reference file json> <optional commit hash>");
    process.exit(1);
}

const referenceValuesFile = args[0];
const commitHash = args[1] || "latest";

// Load the reference files JSON
const referenceValues = JSON.parse(fs.readFileSync(referenceValuesFile, "utf-8"));

// Start HTML content
let htmlContent = `
<!DOCTYPE html>
<html>
<head>
    <title>TD Integrity Reference Values</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }
        th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #f4f4f4; }
    </style>
</head>
<body>
    <h1>TD Integrity Reference Values</h1>
    <p>Commit: ${commitHash}</p>
    <p>Date: ${new Date().toLocaleString()}</p>
`;

// Generate tables from JSON
Object.entries(referenceValues.reference_values).forEach(([key, value]) => {
    //console.log(key, value);

    htmlContent += `<h2>Source: ${value.source}</h2>`;
    htmlContent += `<table>`;

    Object.entries(value).forEach(([k, v]) => {
        if(k != "source") 
        {
            htmlContent += `<tr>`
            htmlContent += `<td rowspan="4">${k}</td>`
            htmlContent += `</tr>`

            htmlContent += `<tr>`
            htmlContent += `<td>Description</td>`
            htmlContent += `<td>${v.description}</td>`
            htmlContent += `</tr>`

            htmlContent += `<tr>`
            htmlContent += `<td>Evidence Path</td>`
            htmlContent += `<td>${v.evidence_path}</td>`
            htmlContent += `</tr>`

            htmlContent += `<tr>`
            htmlContent += `<td>Expected Value</td>`
            htmlContent += `<td>${JSON.stringify(v.expected_value)}</td>`
            htmlContent += `</tr>`
        }
   });

    htmlContent += `</table>`;

});

// End HTML
htmlContent += `</body></html>`;

// write the content to std out
console.log(htmlContent);
