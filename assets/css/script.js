document.addEventListener('DOMContentLoaded', () => {

    // =========================================================================
    // 기능 1: 코드 블록 복사
    // =========================================================================
    const copyIconSVG = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>`;
    const copiedIconSVG = `<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`;
    
    document.querySelectorAll('.highlight').forEach(block => {
        const button = document.createElement('button');
        button.className = 'copy-button';
        button.innerHTML = copyIconSVG;
        button.title = '코드 복사';
        block.appendChild(button);
        button.addEventListener('click', () => {
            const code = block.querySelector('pre > code').innerText;
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
    });

    // =========================================================================
    // 기능 2: 이미지 확대/축소
    // =========================================================================
    const postContent = document.querySelector('.post-content');
    if (postContent) {
        const images = postContent.getElementsByTagName('img');
        for (const img of images) {
            img.addEventListener('click', function() {
                this.classList.toggle('zoomed');
            });
        }
    }

    // =========================================================================
    // 기능 3: 맨 위로 가기 버튼
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
    // 기능 4: PDF 팝업 모달
    // =========================================================================
    const reportLinks = document.querySelectorAll('.report-container a.download-button');
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
            link.addEventListener('click', function(event) {
                event.preventDefault();
                openModal(this.getAttribute('href'));
            });
        });

        closeBtn.addEventListener('click', closeModal);
        modal.addEventListener('click', (event) => { if (event.target === modal) closeModal(); });
        document.addEventListener('keydown', (event) => { if (event.key === "Escape" && modal.style.display === 'flex') closeModal(); });
    }
});
