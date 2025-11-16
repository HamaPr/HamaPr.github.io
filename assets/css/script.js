document.addEventListener('DOMContentLoaded', () => {
    // =========================================================================
    // 기능 1: 사이드바 스크롤 추적 및 부드러운 이동
    // =========================================================================
    const sidebarLinks = document.querySelectorAll('.sidebar-nav a');
    const sections = document.querySelectorAll('h2[id], h3[id], h4[id], h5[id]');

    // IntersectionObserver가 없으면 기능 실행 중단
    if ('IntersectionObserver' in window && sections.length > 0) {
        const observerOptions = {
            root: null,
            rootMargin: '0px 0px -70% 0px', // 화면 상단 30% 지점에서 활성화
            threshold: 0
        };

        const observer = new IntersectionObserver((entries) => {
            let visibleSectionId = null;
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    visibleSectionId = entry.target.getAttribute('id');
                }
            });

            if (visibleSectionId) {
                 sidebarLinks.forEach(link => {
                    link.classList.remove('active');
                    // href 속성값이 # + id 와 일치하는 링크에 active 클래스 추가
                    if (link.getAttribute('href') === `#${visibleSectionId}`) {
                        link.classList.add('active');
                    }
                });
            }
        }, observerOptions);

        sections.forEach(section => {
            observer.observe(section);
        });
    }


    sidebarLinks.forEach(anchor => {
        // 외부 링크가 아닌 페이지 내부 링크(#)에만 부드러운 스크롤 적용
        if (anchor.getAttribute('href').startsWith('#')) {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const targetId = this.getAttribute('href');
                const targetElement = document.querySelector(targetId);
                
                if (targetElement) {
                    targetElement.scrollIntoView({
                        behavior: 'smooth',
                        block: 'start'
                    });
                }
            });
        }
    });

    // =========================================================================
    // 기능 2: PDF 팝업 모달
    // =========================================================================
    
    // 모달이 이미 HTML에 있는지 확인하고, 없으면 추가
    if (!document.getElementById('pdf-modal')) {
        const modalHTML = `
            <div id="pdf-modal" class="modal">
                <div class="modal-content">
                    <span class="close-button">&times;</span>
                    <iframe id="pdf-viewer" frameborder="0"></iframe>
                </div>
            </div>`;
        document.body.insertAdjacentHTML('beforeend', modalHTML);
    }

    const modal = document.getElementById('pdf-modal');
    const closeBtn = modal.querySelector('.close-button');
    const iframe = document.getElementById('pdf-viewer');
    const reportLinks = document.querySelectorAll('.report-container a.download-button');
    const body = document.body;

    function closeModal() {
        modal.style.display = 'none';
        iframe.src = '';
        body.classList.remove('modal-open');
    }

    function openModal(pdfSrc) {
        iframe.src = pdfSrc;
        modal.style.display = 'flex';
        body.classList.add('modal-open');
    }

    reportLinks.forEach(link => {
        link.addEventListener('click', function(event) {
            event.preventDefault(); 
            const pdfSrc = this.getAttribute('href');
            if (pdfSrc) {
                openModal(pdfSrc);
            }
        });
    });

    closeBtn.addEventListener('click', closeModal);
    
    modal.addEventListener('click', function(event) {
        if (event.target === modal) {
            closeModal();
        }
    });

    document.addEventListener('keydown', function(event) {
        if (event.key === "Escape" && modal.style.display === 'flex') { 
            closeModal();
        }
    });
});
