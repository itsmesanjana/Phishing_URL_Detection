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

    if (result.toLowerCase() === 'phishing') {
        document.getElementById('block-btn').classList.remove('hidden');
        document.getElementById('redirect-btn').classList.add('hidden');
    } else {
        document.getElementById('block-btn').classList.add('hidden');
        document.getElementById('redirect-btn').classList.remove('hidden');
    }

    showSection('result');
}

async function checkUrl(event) {
    event.preventDefault();
    const url = document.getElementById('url').value;

    const response = await fetch('/predict', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'Access-Control-Allow-Origin': '*'
        },
        body: `url=${encodeURIComponent(url)}`
    });

    const data = await response.json();
    showResult(data.result, data.url, data.reasons);
}

async function blockSite() {
    const response = await fetch('/block', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
    });

    const data = await response.json();
    if (data.blocked) {
        alert('This site has been blocked!');
    } else {
        alert('Failed to block the site!');
    }
    showSection('home');
    clearInput();
}

function redirectToSite() {
    const url = document.getElementById('result-url').innerText;
    window.location.href = url;
}

function clearInput() {
    document.getElementById('url').value = '';
    document.getElementById('result-text').innerText = '';
    document.getElementById('result-url').innerText = '';
    document.getElementById('reasons').innerHTML = '';
}
function submitFeedback() {
// Try to find the selected radio button for feedback
const feedbackInput = document.querySelector('input[name="feedback"]:checked');

// Check if a radio button is selected
if (!feedbackInput) {
alert("Please select your feedback.");
return; // Stop the function execution if no feedback is selected
}

const feedback = feedbackInput.value; // Now safe to access the value
const reason = document.getElementById('feedback-reason').value;
const url = document.getElementById('url-input').value; // Assuming URL input field has id='url-input'

// Send feedback to the backend via an API call
fetch('/submit-feedback', {
method: 'POST',
headers: {
    'Content-Type': 'application/json',
},
body: JSON.stringify({
    url: url,
    feedback: feedback,
    reason: reason,
}),
})
.then(response => response.json())
.then(data => {
alert("Thank you for your feedback!");
})
.catch(error => {
console.error('Error submitting feedback:', error);
});
}

