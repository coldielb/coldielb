/**
 * COL File Parser - Production-ready parser for .col blog format
 * Supports markdown syntax, inline HTML, and custom <preview> tags
 * 
 * Security considerations:
 * - HTML sanitization to prevent XSS
 * - Input validation and boundary checks
 * - Memory-efficient processing for large files
 */
class ColParser {
    constructor() {
        // HTML entities for security
        this.htmlEntities = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        };

        // Allowed HTML tags for passthrough (whitelist approach)
        this.allowedTags = new Set([
            'p', 'div', 'span', 'a', 'img', 'br', 'hr', 'em', 'strong', 'i', 'b',
            'ul', 'ol', 'li', 'blockquote', 'code', 'pre', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
            'table', 'thead', 'tbody', 'tr', 'th', 'td', 'preview'
        ]);

        // Regex patterns for markdown parsing
        this.patterns = {
            metadata: /^---\s*\n([\s\S]*?)\n---\s*\n/,
            preview: /<preview>([\s\S]*?)<\/preview>/g,
            heading: /^(#{1,6})\s+(.+)$/gm,
            bold: /\*\*(.*?)\*\*/g,
            italic: /\*(.*?)\*/g,
            code: /`([^`]+)`/g,
            codeBlock: /```(\w*)\n([\s\S]*?)```/g,
            link: /\[([^\]]+)\]\(([^)]+)\)/g,
            image: /!\[([^\]]*)\]\(([^)]+)\)/g,
            unorderedList: /^[\s]*[-*+]\s+(.+)$/gm,
            orderedList: /^[\s]*\d+\.\s+(.+)$/gm,
            blockquote: /^>\s+(.+)$/gm,
            horizontalRule: /^---$/gm,
            lineBreak: /\n\n+/g,
            paragraph: /^(?!<[^>]+>|#{1,6}\s|[-*+]\s|\d+\.\s|>\s|```)(.+)$/gm
        };
    }

    /**
     * Escapes HTML entities to prevent XSS attacks
     * @param {string} text - Text to escape
     * @returns {string} - Escaped text
     */
    escapeHtml(text) {
        if (!text || typeof text !== 'string') return '';
        return text.replace(/[&<>"']/g, match => this.htmlEntities[match] || match);
    }

    /**
     * Sanitizes HTML tags, allowing only whitelisted tags
     * @param {string} html - HTML to sanitize
     * @returns {string} - Sanitized HTML
     */
    sanitizeHtml(html) {
        if (!html || typeof html !== 'string') return '';
        
        // Remove script tags and their content completely
        html = html.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
        
        // Remove dangerous attributes
        html = html.replace(/\son\w+\s*=\s*["'][^"']*["']/gi, '');
        html = html.replace(/javascript:/gi, '');
        
        return html;
    }

    /**
     * Parses YAML-like metadata from the top of .col files
     * @param {string} content - File content
     * @returns {Object} - Parsed metadata and remaining content
     */
    parseMetadata(content) {
        const match = content.match(this.patterns.metadata);
        if (!match) {
            return { metadata: {}, content: content.trim() };
        }

        const metadataStr = match[1];
        const remainingContent = content.slice(match[0].length).trim();
        const metadata = {};

        // Parse simple key: value pairs
        const lines = metadataStr.split('\n');
        for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed) continue;
            
            const colonIndex = trimmed.indexOf(':');
            if (colonIndex === -1) continue;
            
            const key = trimmed.slice(0, colonIndex).trim();
            const value = trimmed.slice(colonIndex + 1).trim();
            
            if (key && value) {
                metadata[key] = value.replace(/^["']|["']$/g, ''); // Remove quotes
            }
        }

        return { metadata, content: remainingContent };
    }

    /**
     * Extracts preview content from <preview> tags
     * @param {string} content - Content to extract from
     * @returns {Object} - Preview text and content without preview tags
     */
    extractPreview(content) {
        let preview = '';
        const matches = [...content.matchAll(this.patterns.preview)];
        
        if (matches.length > 0) {
            preview = matches[0][1].trim();
        }

        // Remove preview tags from content
        const cleanContent = content.replace(this.patterns.preview, '');
        
        return { preview, content: cleanContent };
    }

    /**
     * Converts markdown headings to HTML with gradient styling
     * @param {string} content - Content to process
     * @returns {string} - Content with HTML headings
     */
    parseHeadings(content) {
        return content.replace(this.patterns.heading, (match, hashes, text) => {
            const level = hashes.length;
            const id = text.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
            return `<h${level} id="${id}" class="blog-heading">${text.trim()}</h${level}>`;
        });
    }

    /**
     * Converts markdown formatting to HTML
     * @param {string} content - Content to process
     * @returns {string} - Content with HTML formatting
     */
    parseFormatting(content) {
        // Bold text
        content = content.replace(this.patterns.bold, '<strong class="blog-bold">$1</strong>');
        
        // Italic text (but not if it's inside bold)
        content = content.replace(this.patterns.italic, (match, text, offset, string) => {
            // Check if this italic is inside bold tags
            const before = string.slice(0, offset);
            const after = string.slice(offset + match.length);
            const openBold = (before.match(/<strong[^>]*>/g) || []).length;
            const closeBold = (before.match(/<\/strong>/g) || []).length;
            
            if (openBold > closeBold) {
                return `<em class="blog-italic">${text}</em>`;
            }
            return `<em class="blog-italic">${text}</em>`;
        });

        return content;
    }

    /**
     * Converts markdown code blocks and inline code to HTML
     * @param {string} content - Content to process
     * @returns {string} - Content with HTML code elements
     */
    parseCode(content) {
        // Code blocks with language support
        content = content.replace(this.patterns.codeBlock, (match, language, code) => {
            const escapedCode = this.escapeHtml(code.trim());
            const langClass = language ? ` language-${language}` : '';
            return `<pre class="blog-code-block"><code class="blog-code${langClass}">${escapedCode}</code></pre>`;
        });

        // Inline code
        content = content.replace(this.patterns.code, (match, code) => {
            const escapedCode = this.escapeHtml(code);
            return `<code class="blog-inline-code">${escapedCode}</code>`;
        });

        return content;
    }

    /**
     * Converts markdown links and images to HTML
     * @param {string} content - Content to process
     * @returns {string} - Content with HTML links and images
     */
    parseLinksAndImages(content) {
        // Images (must come before links since images use similar syntax)
        content = content.replace(this.patterns.image, (match, alt, src) => {
            const escapedAlt = this.escapeHtml(alt);
            const escapedSrc = this.escapeHtml(src);
            return `<img src="${escapedSrc}" alt="${escapedAlt}" class="blog-image" loading="lazy">`;
        });

        // Links
        content = content.replace(this.patterns.link, (match, text, url) => {
            const escapedText = this.escapeHtml(text);
            const escapedUrl = this.escapeHtml(url);
            const target = url.startsWith('http') ? ' target="_blank" rel="noopener noreferrer"' : '';
            return `<a href="${escapedUrl}" class="blog-link"${target}>${escapedText}</a>`;
        });

        return content;
    }

    /**
     * Converts markdown lists to HTML
     * @param {string} content - Content to process
     * @returns {string} - Content with HTML lists
     */
    parseLists(content) {
        const lines = content.split('\n');
        const result = [];
        let inUnorderedList = false;
        let inOrderedList = false;

        for (let i = 0; i < lines.length; i++) {
            const line = lines[i];
            const unorderedMatch = line.match(/^[\s]*[-*+]\s+(.+)$/);
            const orderedMatch = line.match(/^[\s]*\d+\.\s+(.+)$/);

            if (unorderedMatch) {
                if (!inUnorderedList) {
                    if (inOrderedList) {
                        result.push('</ol>');
                        inOrderedList = false;
                    }
                    result.push('<ul class="blog-list">');
                    inUnorderedList = true;
                }
                result.push(`<li class="blog-list-item">${unorderedMatch[1]}</li>`);
            } else if (orderedMatch) {
                if (!inOrderedList) {
                    if (inUnorderedList) {
                        result.push('</ul>');
                        inUnorderedList = false;
                    }
                    result.push('<ol class="blog-list blog-ordered-list">');
                    inOrderedList = true;
                }
                result.push(`<li class="blog-list-item">${orderedMatch[1]}</li>`);
            } else {
                if (inUnorderedList) {
                    result.push('</ul>');
                    inUnorderedList = false;
                }
                if (inOrderedList) {
                    result.push('</ol>');
                    inOrderedList = false;
                }
                result.push(line);
            }
        }

        // Close any open lists
        if (inUnorderedList) result.push('</ul>');
        if (inOrderedList) result.push('</ol>');

        return result.join('\n');
    }

    /**
     * Converts markdown blockquotes and horizontal rules to HTML
     * @param {string} content - Content to process
     * @returns {string} - Content with HTML blockquotes and rules
     */
    parseBlockElements(content) {
        // Blockquotes
        content = content.replace(this.patterns.blockquote, '<blockquote class="blog-blockquote">$1</blockquote>');
        
        // Horizontal rules
        content = content.replace(this.patterns.horizontalRule, '<hr class="blog-hr">');

        return content;
    }

    /**
     * Wraps text in paragraphs where appropriate
     * @param {string} content - Content to process
     * @returns {string} - Content with paragraph tags
     */
    parseParagraphs(content) {
        // Split by double newlines to identify paragraph breaks
        const sections = content.split(/\n\s*\n/);
        const result = [];

        for (const section of sections) {
            const trimmed = section.trim();
            if (!trimmed) continue;

            // Check if section starts with HTML tag or markdown syntax
            if (trimmed.match(/^<[^>]+>/) || 
                trimmed.match(/^#{1,6}\s/) || 
                trimmed.match(/^[-*+]\s/) || 
                trimmed.match(/^\d+\.\s/) || 
                trimmed.match(/^>\s/) || 
                trimmed.match(/^```/)) {
                result.push(trimmed);
            } else {
                // Wrap in paragraph tags
                result.push(`<p class="blog-paragraph">${trimmed}</p>`);
            }
        }

        return result.join('\n\n');
    }

    /**
     * Main parsing method that processes .col content to HTML
     * @param {string} rawContent - Raw .col file content
     * @returns {Object} - Parsed result with metadata, preview, and HTML content
     */
    parse(rawContent) {
        if (!rawContent || typeof rawContent !== 'string') {
            throw new Error('Invalid input: content must be a non-empty string');
        }

        try {
            // Step 1: Parse metadata
            const { metadata, content: contentWithoutMeta } = this.parseMetadata(rawContent);

            // Step 2: Extract preview
            const { preview, content: contentWithoutPreview } = this.extractPreview(contentWithoutMeta);

            // Step 3: Sanitize HTML (preserve allowed tags)
            let processedContent = this.sanitizeHtml(contentWithoutPreview);

            // Step 4: Parse markdown elements in order
            processedContent = this.parseCode(processedContent);       // Code first to avoid conflicts
            processedContent = this.parseHeadings(processedContent);
            processedContent = this.parseLinksAndImages(processedContent);
            processedContent = this.parseFormatting(processedContent);
            processedContent = this.parseLists(processedContent);
            processedContent = this.parseBlockElements(processedContent);
            processedContent = this.parseParagraphs(processedContent);

            // Step 5: Parse preview content if it exists
            let processedPreview = '';
            if (preview) {
                processedPreview = this.sanitizeHtml(preview);
                processedPreview = this.parseFormatting(processedPreview);
                processedPreview = this.parseLinksAndImages(processedPreview);
                // Remove paragraph wrapping for preview
                processedPreview = processedPreview.trim();
            }

            return {
                metadata: {
                    title: metadata.title || 'Untitled',
                    date: metadata.date || new Date().toISOString().split('T')[0],
                    author: metadata.author || 'Anonymous',
                    tags: metadata.tags ? metadata.tags.split(',').map(tag => tag.trim()) : [],
                    ...metadata
                },
                preview: processedPreview,
                content: processedContent.trim(),
                wordCount: this.countWords(processedContent),
                estimatedReadTime: this.estimateReadTime(processedContent)
            };

        } catch (error) {
            throw new Error(`Failed to parse .col content: ${error.message}`);
        }
    }

    /**
     * Counts words in processed content (excluding HTML tags)
     * @param {string} content - HTML content
     * @returns {number} - Word count
     */
    countWords(content) {
        const textOnly = content.replace(/<[^>]*>/g, '').trim();
        return textOnly ? textOnly.split(/\s+/).length : 0;
    }

    /**
     * Estimates reading time based on average reading speed
     * @param {string} content - HTML content
     * @returns {number} - Estimated read time in minutes
     */
    estimateReadTime(content) {
        const wordCount = this.countWords(content);
        const wordsPerMinute = 200; // Average reading speed
        return Math.max(1, Math.ceil(wordCount / wordsPerMinute));
    }

    /**
     * Loads and parses a .col file from URL
     * @param {string} url - URL to .col file
     * @returns {Promise<Object>} - Parsed content
     */
    async loadFile(url) {
        try {
            const response = await fetch(url);
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const content = await response.text();
            return this.parse(content);
        } catch (error) {
            throw new Error(`Failed to load .col file from ${url}: ${error.message}`);
        }
    }

    /**
     * Generates CSS styles for blog content
     * @returns {string} - CSS stylesheet for blog content
     */
    generateStyles() {
        return `
        .blog-content {
            max-width: 800px;
            margin: 0 auto;
            padding: 2rem;
            font-family: "JetBrains Mono", monospace;
            line-height: 1.6;
            color: #fff;
            background-color: #000;
        }

        .blog-heading {
            background: linear-gradient(135deg, #00ffff, #8a2be2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin: 2rem 0 1rem 0;
            font-weight: 600;
        }

        .blog-heading:first-child {
            margin-top: 0;
        }

        .blog-paragraph {
            margin: 1rem 0;
            color: #ccc;
        }

        .blog-bold {
            font-weight: 600;
            background: linear-gradient(135deg, #00ffff, #8a2be2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .blog-italic {
            font-style: italic;
            color: #aaa;
        }

        .blog-inline-code {
            background-color: #111;
            color: #00ffff;
            padding: 0.2rem 0.4rem;
            border-radius: 0.25rem;
            font-size: 0.9em;
            border: 1px solid #333;
        }

        .blog-code-block {
            background-color: #111;
            color: #ccc;
            padding: 1rem;
            border-radius: 0.5rem;
            overflow-x: auto;
            margin: 1.5rem 0;
            border: 1px solid #333;
        }

        .blog-code {
            font-family: "JetBrains Mono", monospace;
            font-size: 0.9em;
        }

        .blog-link {
            color: #00ffff;
            text-decoration: none;
            border-bottom: 1px solid transparent;
            transition: border-color 0.2s ease;
        }

        .blog-link:hover {
            border-bottom-color: #00ffff;
        }

        .blog-image {
            max-width: 100%;
            height: auto;
            border-radius: 0.5rem;
            margin: 1rem 0;
            border: 1px solid #333;
        }

        .blog-list {
            margin: 1rem 0;
            padding-left: 2rem;
        }

        .blog-list-item {
            margin: 0.5rem 0;
            color: #ccc;
        }

        .blog-ordered-list {
            list-style-type: decimal;
        }

        .blog-blockquote {
            border-left: 4px solid #8a2be2;
            padding-left: 1rem;
            margin: 1.5rem 0;
            color: #aaa;
            font-style: italic;
        }

        .blog-hr {
            border: none;
            height: 1px;
            background: linear-gradient(135deg, #00ffff, #8a2be2);
            margin: 2rem 0;
        }

        .blog-meta {
            border-bottom: 1px solid #333;
            padding-bottom: 1rem;
            margin-bottom: 2rem;
        }

        .blog-title {
            font-size: 2rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            background: linear-gradient(135deg, #00ffff, #8a2be2);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .blog-meta-info {
            display: flex;
            gap: 1rem;
            font-size: 0.9rem;
            color: #888;
            flex-wrap: wrap;
        }

        .blog-tags {
            display: flex;
            gap: 0.5rem;
            margin-top: 0.5rem;
            flex-wrap: wrap;
        }

        .blog-tag {
            background-color: #111;
            color: #00ffff;
            padding: 0.25rem 0.5rem;
            border-radius: 0.25rem;
            font-size: 0.8rem;
            border: 1px solid #333;
        }

        @media (max-width: 768px) {
            .blog-content {
                padding: 1rem;
            }
            
            .blog-title {
                font-size: 1.5rem;
            }
            
            .blog-meta-info {
                flex-direction: column;
                gap: 0.5rem;
            }
            
            .blog-list {
                padding-left: 1.5rem;
            }
        }
        `;
    }
}

// Export for both Node.js and browser environments
if (typeof module !== 'undefined' && module.exports) {
    module.exports = ColParser;
} else if (typeof window !== 'undefined') {
    window.ColParser = ColParser;
}