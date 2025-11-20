document.addEventListener('DOMContentLoaded', () => {
  const tocContainer = document.querySelector('.sidebar-toc');
  const contentContainer = document.querySelector('.post-content');

  if (!tocContainer || !contentContainer) return;

  // 1. TOC 생성
  const headers = contentContainer.querySelectorAll('h1, h2, h3, h4');
  if (headers.length === 0) return;

  const tocList = document.createElement('ul');
  let currentLevel = 1;
  let currentList = tocList;
  const listStack = [tocList]; // 중첩 리스트 관리를 위한 스택

  headers.forEach((header, index) => {
    // ID가 없으면 생성 (공백을 하이픈으로, 특수문자 제거 등 간단한 처리)
    if (!header.id) {
      header.id = 'toc-' + index;
    }

    const level = parseInt(header.tagName.substring(1));
    const link = document.createElement('a');
    link.href = '#' + header.id;
    link.textContent = header.textContent;
    link.className = `toc-h${level}`;
    link.dataset.target = header.id;

    const li = document.createElement('li');
    li.appendChild(link);

    // 레벨에 따른 리스트 구조 처리
    if (level > currentLevel) {
      // 하위 레벨로 진입: 새로운 ul 생성 및 스택에 추가
      const newList = document.createElement('ul');
      newList.className = 'sub-toc';
      
      // H3, H4는 초기에 접어두기 (선택 사항)
      if (level >= 3) {
        newList.classList.add('collapsed');
      }
      
      // 이전 li에 하위 리스트 추가 (마지막 li가 없을 경우 대비 로직 필요하지만, 보통 순차적이므로)
      const lastLi = currentList.lastElementChild;
      if (lastLi) {
        lastLi.appendChild(newList);
        currentList = newList;
        listStack.push(currentList);
      } else {
        // 부모가 없는 경우 (예: H1 없이 H2 시작) 그냥 현재 리스트에 추가
        currentList.appendChild(li);
      }
    } else if (level < currentLevel) {
      // 상위 레벨로 복귀: 스택에서 pop
      while (level < currentLevel && listStack.length > 1) {
        listStack.pop();
        currentLevel--; // 대략적인 레벨 추적 (정확하지 않을 수 있음, 스택 길이로 판단)
      }
      currentList = listStack[listStack.length - 1];
      // 정확한 레벨 매칭을 위해 추가 로직이 필요할 수 있으나, 단순화
    }
    
    // 현재 레벨 유지 또는 상위 복귀 후 추가
    if (level <= currentLevel || (level > currentLevel && !currentList.lastElementChild?.querySelector('ul'))) {
       currentList.appendChild(li);
    }
    
    currentLevel = level;
  });

  tocContainer.appendChild(tocList);

  // 2. 스크롤 스파이 (Scroll Spy)
  const tocLinks = tocContainer.querySelectorAll('a');
  const headerMap = new Map();
  
  headers.forEach(header => headerMap.set(header.id, header));

  const observerOptions = {
    root: null,
    rootMargin: '-100px 0px -60% 0px', // 화면 상단 100px, 하단 60% 지점을 기준으로 감지
    threshold: 0
  };

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const id = entry.target.id;
        activateTocItem(id);
      }
    });
  }, observerOptions);

  headers.forEach(header => observer.observe(header));

  function activateTocItem(id) {
    // 모든 활성 클래스 제거
    tocLinks.forEach(link => link.classList.remove('active'));

    // 해당 ID의 링크 활성화
    const activeLink = tocContainer.querySelector(`a[data-target="${id}"]`);
    if (activeLink) {
      activeLink.classList.add('active');
      
      // 부모 리스트 펼치기
      let parent = activeLink.parentElement.parentElement; // ul
      while (parent && parent.classList.contains('sub-toc')) {
        parent.classList.remove('collapsed');
        parent = parent.parentElement.parentElement;
      }

      // TOC 스크롤 위치 조정
      activeLink.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  }

  // 3. 클릭 이벤트 (부드러운 스크롤 및 수동 활성화)
  tocLinks.forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      const targetId = link.dataset.target;
      const targetElement = document.getElementById(targetId);
      
      if (targetElement) {
        // 헤더 위치로 스크롤 (헤더 높이 등 고려)
        const headerOffset = 80; // 고정 헤더 높이 고려
        const elementPosition = targetElement.getBoundingClientRect().top;
        const offsetPosition = elementPosition + window.pageYOffset - headerOffset;

        window.scrollTo({
          top: offsetPosition,
          behavior: "smooth"
        });
        
        // 클릭 시 즉시 활성화 처리
        activateTocItem(targetId);
      }
    });
  });
});
