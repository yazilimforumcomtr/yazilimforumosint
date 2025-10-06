(() => {
    const catalogDataEl = document.getElementById('tool-catalog-data');
    const systemStatsEl = document.getElementById('system-stats-data');
    if (!catalogDataEl || !systemStatsEl) {
        return;
    }

    const catalog = JSON.parse(catalogDataEl.textContent || '[]');
    const systemStats = JSON.parse(systemStatsEl.textContent || '{}');

    const state = {
        catalog,
        flatTools: buildFlatToolList(catalog),
        filteredTools: [],
        selectedTool: null,
        viewMode: 'pretty',
    };

const CATEGORY_META = {
        'Kişi İstihbaratı': { slug: 'person', color: '#4d7cff' },
        'Site İstihbaratı': { slug: 'site', color: '#31f59b' },
        'Sosyal Medya': { slug: 'social', color: '#ff7ce6' },
        'Medya Analizi': { slug: 'media', color: '#ffb347' },
        'Yardımcı Araçlar': { slug: 'utility', color: '#ff5f5f' },
    };

    function getCategoryMeta(name) {
        return CATEGORY_META[name] || CATEGORY_META['Kişi İstihbaratı'];
    }

    const sidebarEl = document.getElementById('tool-groups');
    const gridEl = document.getElementById('tool-grid');
    const overviewEl = document.getElementById('tool-overview');
    const formEl = document.getElementById('tool-form');
    const resultPanelEl = document.getElementById('result-panel');
    const resultJsonEl = document.getElementById('result-json');
    const resultPrettyEl = document.getElementById('result-pretty');
    const heroStatsEl = document.getElementById('hero-stats');
    if (resultPanelEl) {
        resultPanelEl.style.display = 'none';
    }
    const searchInput = document.getElementById('tool-search');

    state.filteredTools = [...state.flatTools].sort((a, b) => a.name.localeCompare(b.name, 'tr'));

    renderSidebar();
    renderHeroStats();
    renderToolGrid();

    document.getElementById('explore-tools')?.addEventListener('click', () => {
        document.querySelector('.tool-browser')?.scrollIntoView({ behavior: 'smooth' });
    });

    document.getElementById('view-stats')?.addEventListener('click', () => {
        showToast(
            `Sistem: ${systemStats.system?.platform || 'bilinmiyor'} • Araçlar: ${systemStats.tool_count} • Kategoriler: ${systemStats.categories?.length || 0}`,
            'info',
        );
    });

    document.getElementById('copy-result')?.addEventListener('click', async () => {
        const content = resultJsonEl?.textContent || '';
        if (!content.trim()) {
            showToast('Kopyalanacak bir sonuç yok.', 'error');
            return;
        }
        try {
            await navigator.clipboard.writeText(content);
            showToast('Sonuç panoya kopyalandı.', 'success');
        } catch (error) {
            showToast('Kopyalama başarısız oldu.', 'error');
        }
    });

    document.getElementById('toggle-view')?.addEventListener('click', () => {
        state.viewMode = state.viewMode === 'pretty' ? 'json' : 'pretty';
        updateResultVisibility();
    });

    searchInput?.addEventListener('input', (event) => {
        const value = event.target.value.trim().toLowerCase();
        if (!value) {
            state.filteredTools = [...state.flatTools];
        } else {
            state.filteredTools = state.flatTools.filter((tool) => {
                return (
                    tool.name.toLowerCase().includes(value) ||
                    tool.description.toLowerCase().includes(value) ||
                    tool.category.toLowerCase().includes(value) ||
                    tool.tags.some((tag) => tag.toLowerCase().includes(value))
                );
            });
        }
        state.filteredTools.sort((a, b) => a.name.localeCompare(b.name, 'tr'));
        renderToolGrid();
    });

    function renderSidebar() {
        if (!sidebarEl) {
            return;
        }
        sidebarEl.innerHTML = '';
        const categoryIcons = {
            'Kişi İstihbaratı': '👤',
            'Site İstihbaratı': '🌐',
            'Sosyal Medya': '💬',
            'Medya Analizi': '🖼️',
            'Yardımcı Araçlar': '🛠️',
        };

        catalog.forEach((category) => {
            const meta = getCategoryMeta(category.name);
            const wrapper = document.createElement('div');
            wrapper.className = 'sidebar-category';

            const header = document.createElement('div');
            header.className = 'sidebar-category__header';
            const icon = document.createElement('div');
            icon.className = `sidebar-category__icon sidebar-category__icon--${meta.slug}`;
            icon.textContent = categoryIcons[category.name] || '🧭';
            const title = document.createElement('div');
            title.className = 'sidebar-category__title';
            title.textContent = category.name;
            header.append(icon, title);

            const toolList = document.createElement('div');
            category.tools.forEach((tool) => {
                const item = document.createElement('div');
                item.className = `sidebar-tool sidebar-tool--${meta.slug}`;
                item.dataset.toolId = tool.id;
                item.innerHTML = `<span>${tool.name}</span>`;
                item.addEventListener('click', () => selectTool(tool.id));
                toolList.appendChild(item);
            });

            wrapper.append(header, toolList);
            sidebarEl.appendChild(wrapper);
        });
    }

    function renderHeroStats() {
        if (!heroStatsEl) {
            return;
        }
        heroStatsEl.innerHTML = '';
        const items = [
            { label: 'Aktif Araç', value: systemStats.tool_count || state.flatTools.length },
            { label: 'Kategori', value: systemStats.categories?.length || catalog.length },
            { label: 'Şifreli Kayıt', value: systemStats.encrypted_files || 0 },
        ];
        items.forEach(({ label, value }) => {
            const card = document.createElement('div');
            card.className = 'stat-card';
            card.innerHTML = `<h4>${label}</h4><strong>${value}</strong>`;
            heroStatsEl.appendChild(card);
        });
    }

    function renderToolGrid() {
        if (!gridEl) {
            return;
        }
        gridEl.innerHTML = '';
        if (!state.filteredTools.length) {
            const empty = document.createElement('div');
            empty.className = 'tool-card';
            empty.innerHTML = '<h3>Sonuç bulunamadı</h3><p>Aramanızı genişletmeyi deneyin.</p>';
            gridEl.appendChild(empty);
            return;
        }

        state.filteredTools.forEach((tool) => {
            const meta = getCategoryMeta(tool.category);
            const card = document.createElement('div');
            card.className = `tool-card tool-card--${meta.slug}`;
            card.dataset.toolId = tool.id;
            card.dataset.category = meta.slug;
            const tagMarkup = (tool.tags || []).map((tag) => `<span class="tag tag--${meta.slug}">${tag}</span>`).join('');
            card.innerHTML = `
                <div>
                    <h3>${tool.name}</h3>
                    <p>${tool.description}</p>
                </div>
                <div class="tool-card__tags">
                    ${tagMarkup}
                </div>
            `;
            card.addEventListener('click', () => selectTool(tool.id));
            if (state.selectedTool?.id === tool.id) {
                card.classList.add('active');
            }
            gridEl.appendChild(card);
        });
    }

    function selectTool(toolId) {
        const tool = state.flatTools.find((item) => item.id === toolId);
        if (!tool) {
            showToast('Araç bulunamadı.', 'error');
            return;
        }
        state.selectedTool = tool;
        updateActiveStates(toolId);
        renderToolDetail(tool);
        const detailSection = document.querySelector('.tool-detail');
        if (detailSection) {
            detailSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }

    function updateActiveStates(toolId) {
        document.querySelectorAll('.sidebar-tool').forEach((el) => {
            el.classList.toggle('active', el.dataset.toolId === toolId);
        });
        document.querySelectorAll('.tool-card').forEach((el) => {
            el.classList.toggle('active', el.dataset.toolId === toolId);
        });
    }

    function renderToolDetail(tool) {
        if (!overviewEl || !formEl) {
            return;
        }

        const meta = getCategoryMeta(tool.category);
        const tagMarkup = (tool.tags || []).map((tag) => `<span class="tag tag--${meta.slug}">${tag}</span>`).join('');

        overviewEl.innerHTML = `
            <div class="badge badge--${meta.slug}">${tool.category}</div>
            <h3 class="title">${tool.name}</h3>
            <p class="description">${tool.description}</p>
            <div class="tool-card__tags">
                ${tagMarkup}
            </div>
        `;

        const form = document.createElement('form');
        tool.inputs.forEach((field) => {
            form.appendChild(createFieldElement(field));
        });

        const submit = document.createElement('button');
        submit.type = 'submit';
        submit.className = 'btn btn-primary';
        submit.textContent = 'Analizi Başlat';
        form.appendChild(submit);

        form.addEventListener('submit', (event) => {
            event.preventDefault();
            const formData = new FormData(form);
            const payload = {};
            formData.forEach((value, key) => {
                payload[key] = value;
            });
            runTool(tool, payload, submit);
        });

        formEl.innerHTML = '';
        formEl.appendChild(form);
        const firstField = form.querySelector('input, textarea, select');
        if (firstField) {
            firstField.focus();
        }
    }

    function createFieldElement(field) {
        const wrapper = document.createElement('div');
        wrapper.className = 'form-field';
        const id = `field-${field.name}`;
        const label = document.createElement('label');
        label.setAttribute('for', id);
        label.textContent = field.label || field.name;
        wrapper.appendChild(label);

        if (field.type === 'textarea') {
            const textarea = document.createElement('textarea');
            textarea.id = id;
            textarea.name = field.name;
            textarea.placeholder = field.placeholder || '';
            textarea.required = Boolean(field.required);
            wrapper.appendChild(textarea);
        } else if (field.type === 'select') {
            const select = document.createElement('select');
            select.id = id;
            select.name = field.name;
            select.required = Boolean(field.required);
            (field.options || []).forEach((option) => {
                const opt = document.createElement('option');
                opt.value = option.value;
                opt.textContent = option.label;
                select.appendChild(opt);
            });
            wrapper.appendChild(select);
        } else {
            const input = document.createElement('input');
            input.id = id;
            input.name = field.name;
            input.type = field.type || 'text';
            input.placeholder = field.placeholder || '';
            input.required = Boolean(field.required);
            wrapper.appendChild(input);
        }
        return wrapper;
    }

    async function runTool(tool, payload, submitButton) {
        if (!submitButton) {
            return;
        }
        submitButton.disabled = true;
        submitButton.textContent = 'Çalışıyor...';
        try {
            const response = await fetch(`/api/tools/${tool.id}`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload),
            });
            const data = await response.json();
            if (!data.success) {
                throw new Error(data.error || 'Araç çalıştırılırken bir hata oluştu.');
            }
            showToast(`${tool.name} tamamlandı.`, 'success');
            renderResult(data.result);
        } catch (error) {
            console.error(error);
            showToast(error.message || 'Araç çalıştırılamadı.', 'error');
        } finally {
            submitButton.disabled = false;
            submitButton.textContent = 'Analizi Başlat';
        }
    }

    function renderResult(result) {
        if (!resultPanelEl || !resultJsonEl || !resultPrettyEl) {
            return;
        }
        const json = JSON.stringify(result, null, 2);
        resultJsonEl.textContent = json;
        resultPrettyEl.innerHTML = '';
        traverseResult(result, resultPrettyEl);
        if (resultPanelEl) {
            resultPanelEl.style.display = 'block';
        }
        updateResultVisibility();
        resultPanelEl.scrollIntoView({ behavior: 'smooth' });
    }

    function traverseResult(value, container, parentKey = '') {
        if (value === null || value === undefined) {
            return;
        }
        if (typeof value !== 'object') {
            const item = document.createElement('div');
            item.className = 'result-item';
            item.innerHTML = `
                <h4 class="result-item__title">${parentKey || 'Bilgi'}</h4>
                <div class="result-item__value">${escapeHtml(String(value))}</div>
            `;
            container.appendChild(item);
            return;
        }

        if (Array.isArray(value)) {
            value.forEach((entry, index) => {
                traverseResult(entry, container, `${parentKey} #${index + 1}`);
            });
            return;
        }

        Object.entries(value).forEach(([key, val]) => {
            if (typeof val === 'object' && val !== null) {
                const group = document.createElement('div');
                group.className = 'result-item';
                group.innerHTML = `<h4 class="result-item__title">${key}</h4>`;
                const inner = document.createElement('div');
                inner.className = 'result-subgroup';
                traverseResult(val, inner, key);
                group.appendChild(inner);
                container.appendChild(group);
            } else {
                const item = document.createElement('div');
                item.className = 'result-item';
                item.innerHTML = `
                    <h4 class="result-item__title">${key}</h4>
                    <div class="result-item__value">${escapeHtml(String(val))}</div>
                `;
                container.appendChild(item);
            }
        });
    }

    function updateResultVisibility() {
        if (!resultJsonEl || !resultPrettyEl) {
            return;
        }
        if (state.viewMode === 'json') {
            resultJsonEl.style.display = 'block';
            resultPrettyEl.style.display = 'none';
        } else {
            resultJsonEl.style.display = 'none';
            resultPrettyEl.style.display = 'grid';
        }
    }

    function showToast(message, type = 'info') {
        const container = document.getElementById('toast-container');
        if (!container) {
            return;
        }
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        toast.textContent = message;
        container.appendChild(toast);
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(12px)';
            setTimeout(() => toast.remove(), 220);
        }, 3200);
    }

    function buildFlatToolList(groups) {
        const list = [];
        groups.forEach((group) => {
            group.tools.forEach((tool) => {
                list.push({
                    ...tool,
                    category: group.name,
                });
            });
        });
        return list;
    }

    function escapeHtml(value) {
        return value
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#039;');
    }
})();
