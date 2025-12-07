document.addEventListener('DOMContentLoaded', () => {

    // =========================================================================
    // 1: 코드 블록 복사
    // =========================================================================
    const copyIconSVG = `<svg xmlns="http://www.w.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>`;
    const copiedIconSVG = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`;

    document.querySelectorAll('.highlight').forEach(block => {
        const button = document.createElement('button');
        button.className = 'copy-button';
        button.innerHTML = copyIconSVG;
        button.title = '코드 복사';

        const codeElement = block.querySelector('pre > code');

        if (codeElement) {
            block.appendChild(button);
            button.addEventListener('click', () => {
                const code = codeElement.innerText;
                navigator.clipboard.writeText(code).then(() => {
                    button.innerHTML = copiedIconSVG;
                    button.classList.add('copied');
                    button.title = '복사 완료!';
                    setTimeout(() => {
                        button.innerHTML = copyIconSVG;
                        button.classList.remove('copied');
                        button.title = '코드 복사';
                    }, 2000);
                });
            });
        }
    });

    // =========================================================================
    // 2: 이미지 확대/축소
    // =========================================================================
    const postContentForImages = document.querySelector('.post-content');
    if (postContentForImages) {
        if (!document.querySelector('.image-overlay')) {
            const overlay = document.createElement('div');
            overlay.className = 'image-overlay';
            document.body.appendChild(overlay);
        }

        const images = postContentForImages.getElementsByTagName('img');
        const overlay = document.querySelector('.image-overlay');

        for (const img of images) {
            img.addEventListener('click', function (event) {
                if (this.closest('.report-container a')) {
                    return;
                }

                event.preventDefault();

                this.classList.toggle('zoomed');
                overlay.classList.toggle('active');
            });
        }

        overlay.addEventListener('click', function () {
            const zoomedImage = document.querySelector('img.zoomed');
            if (zoomedImage) {
                zoomedImage.classList.remove('zoomed');
                this.classList.remove('active');
            }
        });
    }

    // =========================================================================
    // 3: 맨 위로 가기 버튼
    // =========================================================================
    const backToTopBtn = document.getElementById('back-to-top');
    if (backToTopBtn) {
        window.addEventListener('scroll', () => {
            backToTopBtn.style.display = window.scrollY > 300 ? 'block' : 'none';
        });
        backToTopBtn.addEventListener('click', e => {
            e.preventDefault();
            window.scrollTo({ top: 0, behavior: 'smooth' });
        });
    }

    // =========================================================================
    // 4: PDF 팝업 모달
    // =========================================================================
    const reportLinks = document.querySelectorAll('.report-container a');
    if (reportLinks.length > 0 && !document.getElementById('pdf-modal')) {
        const modalHTML = `<div id="pdf-modal" class="modal"><div class="modal-content"><span class="close-button">&times;</span><iframe id="pdf-viewer" frameborder="0"></iframe></div></div>`;
        document.body.insertAdjacentHTML('beforeend', modalHTML);

        const modal = document.getElementById('pdf-modal');
        const closeBtn = modal.querySelector('.close-button');
        const iframe = document.getElementById('pdf-viewer');

        const closeModal = () => {
            modal.style.display = 'none';
            iframe.src = '';
            document.body.classList.remove('modal-open');
        };
        const openModal = (pdfSrc) => {
            iframe.src = pdfSrc;
            modal.style.display = 'flex';
            document.body.classList.add('modal-open');
        };

        reportLinks.forEach(link => {
            link.addEventListener('click', function (event) {
                event.preventDefault();
                openModal(this.getAttribute('href'));
            });
        });

        closeBtn.addEventListener('click', closeModal);
        modal.addEventListener('click', (event) => { if (event.target === modal) closeModal(); });
        document.addEventListener('keydown', (event) => { if (event.key === "Escape" && modal.style.display === 'flex') closeModal(); });
    }
    // =========================================================================
    // 5: GitHub Style Alert / Callout Block Parsing
    // =========================================================================
    const blockquotes = document.querySelectorAll('.post-content blockquote');
    const infoIconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" width="16" height="16"><path d="M0 8a8 8 0 1 1 16 0A8 8 0 0 1 0 8Zm8-6.5a6.5 6.5 0 1 0 0 13 6.5 6.5 0 0 0 0-13ZM6.5 7.75A.75.75 0 0 1 7.25 7h1a.75.75 0 0 1 .75.75v2.75h.25a.75.75 0 0 1 0 1.5h-2a.75.75 0 0 1 0-1.5h.25v-2h-.25a.75.75 0 0 1-.75-.75ZM8 6a1 1 0 1 1 0-2 1 1 0 0 1 0 2Z"></path></svg>`;

    blockquotes.forEach(quote => {
        const html = quote.innerHTML.trim();
        const noteTag = '[!NOTE]';

        if (html.includes(noteTag)) {
            quote.innerHTML = html.replace(noteTag, '');
            quote.classList.add('callout-block');

            const titleDiv = document.createElement('div');
            titleDiv.className = 'callout-title';
            titleDiv.innerHTML = `${infoIconSVG} Note`;
            quote.prepend(titleDiv);
        }
    });

    // =========================================================================
    // 6: Mermaid Diagram Zoom Interaction
    // =========================================================================
    document.body.addEventListener('click', (event) => {
        const target = event.target.closest('.mermaid svg');
        if (target) {
            target.classList.toggle('zoomed');

            const overlay = document.querySelector('.image-overlay');
            if (overlay) {
                overlay.classList.toggle('active');
            }
        }
    });

    const overlay = document.querySelector('.image-overlay');
    if (overlay) {
        overlay.addEventListener('click', () => {
            const zoomedMermaid = document.querySelector('.mermaid svg.zoomed');
            if (zoomedMermaid) {
                zoomedMermaid.classList.remove('zoomed');
            }
        });
    }
});
