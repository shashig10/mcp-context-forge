/*
 * UPTIMIZE table cell expansion initializer.
 *
 * Adds lightweight metadata/classes to target cells so CSS can:
 * - keep a truncated preview (single-line or multi-line clamp)
 * - show full value in a hover popover without changing table layout
 */
(function () {
    "use strict";

    const CELL_CONFIG = [
        {
            selector: "#gateways-table tbody td:nth-child(3)",
            mode: "url",
            style: "multiline",
            lines: 2,
            minLength: 36,
            maxWidth: "32rem",
        },
        {
            selector: "#servers-table tbody td:nth-child(5)",
            mode: "text",
            style: "multiline",
            lines: 4,
            minLength: 90,
            maxWidth: "34rem",
        },
        {
            selector: "#tools-table tbody td:nth-child(5)",
            mode: "text",
            style: "multiline",
            lines: 3,
            minLength: 85,
            maxWidth: "34rem",
        },
        {
            selector: "#prompts-table tbody td:nth-child(5)",
            mode: "text",
            style: "multiline",
            lines: 3,
            minLength: 80,
            maxWidth: "36rem",
        },
        {
            selector: "#resources-table tbody td:nth-child(3)",
            mode: "text",
            style: "multiline",
            lines: 3,
            minLength: 80,
            maxWidth: "34rem",
        },
        {
            selector: "#agents-table tbody td:nth-child(3)",
            mode: "text",
            style: "multiline",
            lines: 3,
            minLength: 75,
            maxWidth: "34rem",
        },
        {
            selector: "#agents-table tbody td:nth-child(4)",
            mode: "url",
            style: "multiline",
            lines: 2,
            minLength: 30,
            maxWidth: "34rem",
        },
    ];

    function normalizeWhitespace(value) {
        if (!value) {
            return "";
        }
        return value.replace(/\u00a0/g, " ").replace(/[ \t]+\n/g, "\n").replace(/\n{3,}/g, "\n\n").replace(/[ \t]{2,}/g, " ").trim();
    }

    function extractCellText(cell, mode) {
        if (!cell) {
            return "";
        }

        if (mode === "url") {
            const link = cell.querySelector('a[href^="http"], a[href^="https"]');
            if (link && link.getAttribute("href")) {
                return normalizeWhitespace(link.getAttribute("href"));
            }

            const rawText = normalizeWhitespace(cell.innerText || cell.textContent || "");
            const matchedUrl = rawText.match(/https?:\/\/\S+/i);
            return matchedUrl ? matchedUrl[0] : rawText;
        }

        return normalizeWhitespace(cell.innerText || cell.textContent || "");
    }

    function clearCellState(cell) {
        cell.classList.remove("upt-cell-expandable", "upt-expand--singleline", "upt-expand--multiline", "upt-expand--url");
        cell.removeAttribute("data-upt-full-text");
        cell.style.removeProperty("--upt-expand-max-width");
    }

    function ensurePreviewWrapper(cell) {
        let preview = cell.querySelector(":scope > .upt-cell-preview");
        if (preview) {
            return preview;
        }

        preview = document.createElement("span");
        preview.className = "upt-cell-preview";

        while (cell.firstChild) {
            preview.appendChild(cell.firstChild);
        }

        cell.appendChild(preview);
        return preview;
    }

    function applyCellBehavior(cell, config) {
        if (!(cell instanceof HTMLElement)) {
            return;
        }

        clearCellState(cell);

        const fullText = extractCellText(cell, config.mode);
        if (!fullText) {
            return;
        }

        if (fullText.length < (config.minLength || 0)) {
            return;
        }

        ensurePreviewWrapper(cell);

        cell.classList.add("upt-cell-expandable");
        cell.classList.add(config.style === "multiline" ? "upt-expand--multiline" : "upt-expand--singleline");

        if (config.mode === "url") {
            cell.classList.add("upt-expand--url");
        }

        if (config.lines) {
            cell.style.setProperty("--upt-clamp-lines", String(config.lines));
        }

        if (config.maxWidth) {
            cell.style.setProperty("--upt-expand-max-width", config.maxWidth);
        }

        cell.setAttribute("data-upt-full-text", fullText);
    }

    function initializeTableExpansions() {
        CELL_CONFIG.forEach((config) => {
            document.querySelectorAll(config.selector).forEach((cell) => applyCellBehavior(cell, config));
        });
    }

    function scheduleInitialize() {
        window.requestAnimationFrame(() => initializeTableExpansions());
    }

    document.addEventListener("DOMContentLoaded", () => {
        scheduleInitialize();
    });

    document.addEventListener("htmx:afterSwap", () => {
        scheduleInitialize();
    });

    document.addEventListener("click", (event) => {
        if (event.target.closest('[onclick*="showTab"]')) {
            window.setTimeout(() => scheduleInitialize(), 120);
        }
    });

    // Safety pass for first paint + late HTMX content.
    window.addEventListener("load", () => {
        window.setTimeout(() => scheduleInitialize(), 140);
    });

    window.uptimizeInitializeTableExpansions = scheduleInitialize;
})();
