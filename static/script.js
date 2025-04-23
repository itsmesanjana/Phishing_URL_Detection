function showSection(section) {
    document.getElementById('home').classList.add('hidden');
    document.getElementById('result').classList.add('hidden');
    document.getElementById(section).classList.remove('hidden');
}

function showResult(result, url, reasons) {
    document.getElementById('result-text').innerText = result;
    document.getElementById('result-url').innerText = url;

    const reasonsList = document.getElementById('reasons');
    reasonsList.innerHTML = '';
    if (reasons && reasons.length > 0) {
        reasonsList.innerHTML = `<h3>Reasons:</h3><ul>${reasons.map(reason => `<li>${reason}</li>`).join('')}</ul>`;
    }

    const blockBtn = document.getElementById('block-btn');
    const redirectBtn = document.getElementById('redirect-btn');

    if (result.toLowerCase() === 'phishing') {
        if (isBlocked(url)) {
            blockBtn.classList.remove('hidden');
            blockBtn.disabled = true;
            blockBtn.innerText = 'URL Already Blocked';
        } else {
            blockBtn.classList.remove('hidden');
            blockBtn.disabled = false;
            blockBtn.innerText = 'Block This URL';
        }
        redirectBtn.classList.add('hidden');
    } else {
        blockBtn.classList.add('hidden');
        redirectBtn.classList.remove('hidden');
    }

    showSection('result');
}

async function checkUrl(event) {
    event.preventDefault();
    const url = document.getElementById('url').value;

    const response = await fetch('/predict', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `url=${encodeURIComponent(url)}`
    });

    const data = await response.json();
    showResult(data.result, data.url, data.reasons);
}

async function blockSite() {
    const url = document.getElementById('result-url').innerText.trim();

    const response = await fetch('/block', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        },
        body: `url=${encodeURIComponent(url)}`
    });

    const data = await response.json();

    if (data.blocked) {
        saveToBlockedList(url);
        alert('This site has been blocked!');
    } else {
        alert('Failed to block the site!');
    }

    showSection('home');
    clearInput();
}

function redirectToSite() {
    let url = document.getElementById('result-url').innerText;
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url;
    }
    window.location.href = url;
}

function clearInput() {
    document.getElementById('url').value = '';
    document.getElementById('result-text').innerText = '';
    document.getElementById('result-url').innerText = '';
    document.getElementById('reasons').innerHTML = '';
}

// Feedback section
function submitFeedback() {
    const feedbackInput = document.querySelector('input[name="feedback"]:checked');
    if (!feedbackInput) {
        alert("Please select your feedback.");
        return;
    }

    const feedback = feedbackInput.value;
    const reason = document.getElementById('feedback-reason').value;
    const url = document.getElementById('url-input').value;

    fetch('/submit-feedback', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url, feedback, reason })
    })
    .then(response => response.json())
    .then(() => alert("Thank you for your feedback!"))
    .catch(error => console.error('Error submitting feedback:', error));
}

// === Blocked URL Utility Functions ===

function saveToBlockedList(url) {
    let blocked = JSON.parse(localStorage.getItem('blockedURLs')) || [];
    if (!blocked.includes(url)) {
        blocked.push(url);
        localStorage.setItem('blockedURLs', JSON.stringify(blocked));
    }
}

function isBlocked(url) {
    let blocked = JSON.parse(localStorage.getItem('blockedURLs')) || [];
    return blocked.includes(url);
}

function showResult(result, url, reasons) {
    document.getElementById('result-text').innerText = result;
    document.getElementById('result-url').innerText = url;

    const reasonsList = document.getElementById('reasons');
    reasonsList.innerHTML = '';
    if (reasons && reasons.length > 0) {
        reasonsList.innerHTML = `<h3>Reasons:</h3><ul>${reasons.map(reason => `<li>${reason}</li>`).join('')}</ul>`;
    }

    const blockBtn = document.getElementById('block-btn');
    const redirectBtn = document.getElementById('redirect-btn');

    if (result.toLowerCase() === 'phishing') {
        blockBtn.classList.remove('hidden');
        blockBtn.disabled = false;
        blockBtn.innerText = 'Block This URL';
        redirectBtn.classList.add('hidden');
    } else {
        blockBtn.classList.add('hidden');
        redirectBtn.classList.remove('hidden');
    }

    showSection('result');
}

function blockSite() {
    const url = document.getElementById("url").value;

    fetch('/block-url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
    })
    .then(res => res.json())
    .then(data => {
        alert(data.message);
    });
}

function viewBlockedSites() {
    fetch('/get-blocked-urls')
        .then(res => res.json())
        .then(data => {
            const listElement = document.getElementById('blocked-list');
            listElement.innerHTML = '';

            if (data.blocked_urls.length === 0) {
                listElement.innerHTML = '<li>No sites blocked.</li>';
            } else {
                data.blocked_urls.forEach(url => {
                    const li = document.createElement('li');
                    li.innerText = url;
                    listElement.appendChild(li);
                });
            }

            document.getElementById('blocked-sites-modal').classList.remove('hidden');
        });
}
  