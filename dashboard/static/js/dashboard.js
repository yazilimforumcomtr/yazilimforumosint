// YF OSINT Dashboard JavaScript

// Tool definitions
const tools = {
    linkedin_analyzer: {
        title: 'LinkedIn Profil Analizi',
        description: 'LinkedIn profillerini detaylı analiz eder'
    },
    email_breach_checker: {
        title: 'E-posta Sızıntı Kontrolü',
        description: 'E-posta adresinin veri sızıntılarında olup olmadığını kontrol eder'
    },
    phone_location_analyzer: {
        title: 'Telefon Konum ve Ağ Analizi',
        description: 'Telefon numarasının konum ve operatör bilgilerini analiz eder'
    },
    social_cross_check: {
        title: 'Sosyal Medya Cross-Check',
        description: 'Farklı sosyal medya platformlarında aynı kişiyi arar'
    },
    subdomain_ssl_analyzer: {
        title: 'Subdomain Tarama ve SSL Analizi',
        description: 'Subdomainleri tarar ve SSL sertifikalarını analiz eder'
    },
    port_service_scanner: {
        title: 'Açık Port ve Servis Tarama',
        description: 'Açık portları ve çalışan servisleri tarar'
    },
    http_header_analyzer: {
        title: 'HTTP Header Bilgi Analizi',
        description: 'HTTP başlıklarını detaylı analiz eder'
    },
    twitter_activity_analyzer: {
        title: 'Twitter/X Aktivite Analizi',
        description: 'Twitter hesaplarının aktivitelerini analiz eder'
    },
    instagram_post_analyzer: {
        title: 'Instagram Açık Gönderi Analizi',
        description: 'Instagram gönderilerini analiz eder'
    }
};

let currentTool = null;

// Load tool interface
function loadTool(toolId) {
    if (!tools[toolId]) {
        console.error('Tool not found:', toolId);
        return;
    }
    
    currentTool = toolId;
    const tool = tools[toolId];
    
    // Update UI
    document.getElementById('welcome').style.display = 'none';
    document.getElementById('tool-container').style.display = 'block';
    document.getElementById('tool-title').textContent = tool.title;
    document.getElementById('tool-description').textContent = tool.description;
    document.getElementById('results').style.display = 'none';
    
    // Clear form
    document.getElementById('target').value = '';
}

// Handle form submission
document.getElementById('tool-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const target = document.getElementById('target').value.trim();
    if (!target) {
        alert('Lütfen hedef girin!');
        return;
    }
    
    if (!currentTool) {
        alert('Lütfen bir araç seçin!');
        return;
    }
    
    // Show loading
    const resultsContent = document.getElementById('results-content');
    resultsContent.innerHTML = '<div class="loading">Analiz yapılıyor</div>';
    document.getElementById('results').style.display = 'block';
    
    try {
        // Call API
        const response = await fetch('/api/run_tool', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                tool_id: currentTool,
                target: target
            })
        });
        
        const result = await response.json();
        
        if (result.error) {
            resultsContent.innerHTML = `<div style="color: #ff4444;">Hata: ${result.error}</div>`;
        } else {
            // Format result
            resultsContent.innerHTML = formatResult(result);
        }
        
    } catch (error) {
        resultsContent.innerHTML = `<div style="color: #ff4444;">Bağlantı hatası: ${error.message}</div>`;
    }
});

// Format result for display
function formatResult(result) {
    let html = '';
    
    // Tool info
    html += `<div style="color: #00ff00; font-weight: bold; margin-bottom: 1rem;">`;
    html += `Araç: ${result.tool || 'Bilinmiyor'}<br>`;
    html += `Hedef: ${result.target || 'Bilinmiyor'}<br>`;
    html += `Zaman: ${result.timestamp || 'Bilinmiyor'}`;
    html += `</div>`;
    
    // Results
    for (const [key, value] of Object.entries(result)) {
        if (key === 'tool' || key === 'target' || key === 'timestamp') continue;
        
        html += `<div style="margin-bottom: 1rem;">`;
        html += `<div style="color: #00ff00; font-weight: bold; margin-bottom: 0.5rem;">`;
        html += `${key.replace(/_/g, ' ').toUpperCase()}:`;
        html += `</div>`;
        
        if (typeof value === 'object' && value !== null) {
            html += `<div style="margin-left: 1rem;">`;
            html += formatObject(value);
            html += `</div>`;
        } else {
            html += `<div style="color: #e0e0e0; margin-left: 1rem;">${value}</div>`;
        }
        
        html += `</div>`;
    }
    
    return html;
}

// Format object recursively
function formatObject(obj, indent = 0) {
    let html = '';
    const spaces = '  '.repeat(indent);
    
    for (const [key, value] of Object.entries(obj)) {
        html += `<div style="margin-bottom: 0.3rem;">`;
        html += `<span style="color: #ffff00;">${spaces}${key}:</span> `;
        
        if (typeof value === 'object' && value !== null) {
            if (Array.isArray(value)) {
                html += `<div style="margin-left: 1rem;">`;
                value.forEach((item, index) => {
                    html += `<div style="color: #e0e0e0;">${index + 1}. ${item}</div>`;
                });
                html += `</div>`;
            } else {
                html += `<div style="margin-left: 1rem;">`;
                html += formatObject(value, indent + 1);
                html += `</div>`;
            }
        } else {
            html += `<span style="color: #e0e0e0;">${value}</span>`;
        }
        
        html += `</div>`;
    }
    
    return html;
}

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    console.log('YF OSINT Dashboard loaded');
});