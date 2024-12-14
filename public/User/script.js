// Get form elements
const registerForm = document.getElementById('registerForm');
const loginForm = document.getElementById('loginForm');
const uploadForm = document.getElementById('uploadForm');
const userFolderInput = document.getElementById('userFolder');

// Handle Registration

registerForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const formData = new FormData(registerForm);
    const data = Object.fromEntries(formData.entries());

    const response = await fetch('/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    const result = await response.json();
    

    if (result.success) {
        // Redirect to home.html on successful registration
        window.location.href = '/User/home.html'; // Updated URL
    } else {
        alert(result.message);
    }
});

// Handle Login
loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const formData = new FormData(loginForm);
    const data = Object.fromEntries(formData.entries());

    const response = await fetch('/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(data)
    });
    const result = await response.json();

    if (result.success) {
        // Show upload form
        uploadForm.style.display = 'block';

        // Redirect to home.html after login
        window.location.href = '/User/home.html'; // Updated URL
    } else {
        alert(result.message);
    }
});


// Handle File Upload
uploadForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    const formData = new FormData(uploadForm); // Gather form data including file
    const response = await fetch('/upload', {
        method: 'POST',
        body: formData,
    });

    const result = await response.text();
    alert(result); // Alert the response (success/failure message)
});


// Show the correct form when the radio button changes
document.querySelectorAll('input[name="formSwitch"]').forEach(input => {
    input.addEventListener('change', function () {
        if (this.value === 'register') {
            loginForm.style.display = 'none';
            registerForm.style.display = 'block';
        } else {
            registerForm.style.display = 'none';
            loginForm.style.display = 'block';
        }
    });
});

// Show the Login form initially
loginForm.style.display = 'block';