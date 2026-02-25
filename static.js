async function scanURL() {
    const url = document.getElementById('urlInput').value;
    const response = await fetch('/analyze', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({url: url})
    });
    
    const data = await response.json();
    
    document.getElementById('resultCard').classList.remove('hidden');
    document.getElementById('verdict').innerText = "Verdict: " + data.level;
    document.getElementById('scoreText').innerText = (data.score * 100);
    document.getElementById('scoreBar').style.width = (data.score * 100) + "%";
    document.getElementById('entropyText').innerText = data.entropy;

    const list = document.getElementById('warningList');
    list.innerHTML = "";
    data.warnings.forEach(w => {
        let li = document.createElement('li');
        li.innerText = "⚠️ " + w;
        list.appendChild(li);
    });
}