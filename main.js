// Encryption functions
async function generateEncryptionKey(password) {
    const encoder = new TextEncoder();
    const passwordBuffer = encoder.encode(password);
    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const keyMaterial = await window.crypto.subtle.importKey(
        'raw',
        passwordBuffer,
        { name: 'PBKDF2' },
        false,
        ['deriveKey']
    );
    
    return await window.crypto.subtle.deriveKey(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        keyMaterial,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptData(data, password) {
    try {
        const key = await generateEncryptionKey(password);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encoder = new TextEncoder();
        const encodedData = encoder.encode(data);
        
        const encryptedData = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            encodedData
        );
        
        return {
            iv: Array.from(iv).join(','),
            data: Array.from(new Uint8Array(encryptedData)).join(',')
        };
    } catch (error) {
        console.error('Encryption error:', error);
        return null;
    }
}

async function decryptData(encryptedObj, password) {
    try {
        const key = await generateEncryptionKey(password);
        const iv = new Uint8Array(encryptedObj.iv.split(',').map(Number));
        const encryptedData = new Uint8Array(encryptedObj.data.split(',').map(Number));
        
        const decryptedData = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: iv
            },
            key,
            encryptedData
        );
        
        return new TextDecoder().decode(decryptedData);
    } catch (error) {
        console.error('Decryption error:', error);
        return null;
    }
}

// Password management functions
async function addPassword(service, username, password) {
    const currentUser = JSON.parse(localStorage.getItem('currentUser'));
    const masterPassword = localStorage.getItem('currentPassword');
    const users = JSON.parse(localStorage.getItem('users')) || [];
    const user = users.find(u => u.id === currentUser.id);
    
    if (!user || !masterPassword) return false;
    
    try {
        // Decrypt the vault
        const decryptedVault = await decryptData(user.encryptedVault, masterPassword);
        const vault = JSON.parse(decryptedVault);
        
        // Add new password
        vault.passwords.push({
            id: Date.now().toString(),
            service,
            username,
            password,
            createdAt: new Date().toISOString(),
            lastUsed: new Date().toISOString()
        });
        
        // Re-encrypt the vault
        const encryptedVault = await encryptData(JSON.stringify(vault), masterPassword);
        user.encryptedVault = encryptedVault;
        
        // Update user in storage
        localStorage.setItem('users', JSON.stringify(users));
        return true;
    } catch (error) {
        console.error('Error adding password:', error);
        return false;
    }
}

async function getPasswords() {
    const currentUser = JSON.parse(localStorage.getItem('currentUser'));
    const masterPassword = localStorage.getItem('currentPassword');
    const users = JSON.parse(localStorage.getItem('users')) || [];
    const user = users.find(u => u.id === currentUser.id);
    
    if (!user || !masterPassword) return [];
    
    try {
        const decryptedVault = await decryptData(user.encryptedVault, masterPassword);
        const vault = JSON.parse(decryptedVault);
        return vault.passwords || [];
    } catch (error) {
        console.error('Error getting passwords:', error);
        return [];
    }
}

function generateStrongPassword() {
    const chars = "0123456789abcdefghijklmnopqrstuvwxyz!@#$%^&*()ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const length = 16;
    let password = "";
    
    for (let i = 0; i < length; i++) {
        const randomNumber = Math.floor(Math.random() * chars.length);
        password += chars.substring(randomNumber, randomNumber + 1);
    }
    
    return password;
}

// Initialize password management UI
function initPasswordManagement() {
    const addPasswordBtn = document.getElementById('addFirstPassword');
    const addPasswordSidebarBtn = document.getElementById('addPasswordBtn');
    const passwordModal = document.getElementById('passwordModal');
    const closeModal = document.querySelector('.close-modal');
    const generatePasswordBtn = document.getElementById('generatePassword');
    const addPasswordForm = document.getElementById('addPasswordForm');
    
    // Open modal from empty state button
    if (addPasswordBtn) {
        addPasswordBtn.addEventListener('click', () => {
            passwordModal.style.display = 'block';
        });
    }
    
    // Open modal from sidebar button
    if (addPasswordSidebarBtn) {
        addPasswordSidebarBtn.addEventListener('click', (e) => {
            e.preventDefault();
            passwordModal.style.display = 'block';
        });
    }
    
    // Close modal
    if (closeModal) {
        closeModal.addEventListener('click', () => {
            passwordModal.style.display = 'none';
        });
    }
    
    // Generate password
    if (generatePasswordBtn) {
        generatePasswordBtn.addEventListener('click', () => {
            document.getElementById('new-password').value = generateStrongPassword();
        });
    }
    
    // Add new password
    if (addPasswordForm) {
        addPasswordForm.addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const service = document.getElementById('service').value;
            const username = document.getElementById('username').value;
            const password = document.getElementById('new-password').value;
            
            const success = await addPassword(service, username, password);
            
            if (success) {
                passwordModal.style.display = 'none';
                addPasswordForm.reset();
                displayPasswords();
            } else {
                alert('Error saving password');
            }
        });
    }
}

// Display passwords in the UI
async function displayPasswords() {
    const passwords = await getPasswords();
    const passwordList = document.querySelector('.password-list');
    const passwordCount = document.getElementById('passwordCount');
    
    if (!passwordList) return;
    
    // Update password count
    if (passwordCount) {
        passwordCount.textContent = passwords.length;
    }
    
    if (passwords.length === 0) {
        passwordList.innerHTML = `
            <div class="empty-state">
                <i class="fas fa-key"></i>
                <p>No passwords saved yet</p>
                <button id="addFirstPassword" class="btn btn-primary">Add your first password</button>
            </div>
        `;
        initPasswordManagement();
        return;
    }
    
    passwordList.innerHTML = '';
    
    passwords.forEach(pwd => {
        const passwordItem = document.createElement('div');
        passwordItem.className = 'password-item';
        passwordItem.innerHTML = `
            <div class="password-icon">
                <i class="fas fa-lock"></i>
            </div>
            <div class="password-details">
                <h3>${pwd.service}</h3>
                <p>${pwd.username}</p>
                <small>Last used: ${new Date(pwd.lastUsed).toLocaleDateString()}</small>
            </div>
            <div class="password-actions">
                <button class="btn-icon show-password" data-password="${pwd.password}">
                    <i class="fas fa-eye"></i>
                </button>
                <button class="btn-icon copy-password" data-password="${pwd.password}">
                    <i class="fas fa-copy"></i>
                </button>
            </div>
        `;
        passwordList.appendChild(passwordItem);
    });
    
    // Add event listeners for password actions
    document.querySelectorAll('.show-password').forEach(btn => {
        btn.addEventListener('click', function() {
            const password = this.getAttribute('data-password');
            alert(`Password: ${password}`);
        });
    });
    
    document.querySelectorAll('.copy-password').forEach(btn => {
        btn.addEventListener('click', function() {
            const password = this.getAttribute('data-password');
            navigator.clipboard.writeText(password).then(() => {
                alert('Password copied to clipboard!');
            });
        });
    });
}

// Check if user is logged in
function checkAuth() {
    const isLoggedIn = localStorage.getItem('isLoggedIn') === 'true';
    const currentPage = window.location.pathname.split('/').pop();
    
    if (isLoggedIn && (currentPage === 'index.html' || currentPage === 'signup.html')) {
        window.location.href = 'home.html';
    }
    
    if (!isLoggedIn && currentPage === 'home.html') {
        window.location.href = 'index.html';
    }
}

// Form handling
const loginForm = document.querySelector('#loginForm');
const signupForm = document.querySelector('#signupForm');

if (loginForm) {
    loginForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        
        // Get stored users
        const users = JSON.parse(localStorage.getItem('users')) || [];
        
        // Find user by email only (we don't store passwords)
        const user = users.find(u => u.email === email);
        
        if (user) {
            // Try to decrypt the vault to verify password
            try {
                const decryptedVault = await decryptData(user.encryptedVault, password);
                
                if (decryptedVault) {
                    // Password is correct
                    localStorage.setItem('isLoggedIn', 'true');
                    localStorage.setItem('currentUser', JSON.stringify({
                        id: user.id,
                        name: user.name,
                        email: user.email
                    }));
                    localStorage.setItem('currentPassword', password);
                    window.location.href = 'home.html';
                } else {
                    alert('Invalid password');
                }
            } catch (error) {
                alert('Invalid password');
            }
        } else {
            alert('User not found');
        }
    });
}

if (signupForm) {
    signupForm.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        const name = document.getElementById('name').value;
        const email = document.getElementById('email').value;
        const password = document.getElementById('password').value;
        const confirmPassword = document.getElementById('confirm-password').value;
        const terms = document.getElementById('terms').checked;
        
        // Validation
        if (!name || !email || !password || !confirmPassword) {
            alert('Please fill in all fields');
            return;
        }
        
        if (password !== confirmPassword) {
            alert('Passwords do not match!');
            return;
        }
        
        if (!terms) {
            alert('You must agree to the terms and conditions');
            return;
        }
        
        // Get existing users
        const users = JSON.parse(localStorage.getItem('users')) || [];
        
        // Check if user already exists
        if (users.some(u => u.email === email)) {
            alert('User with this email already exists');
            return;
        }
        
        // Create a master password encrypted vault
        const vault = {
            passwords: []
        };
        
        // Encrypt the vault with the user's master password
        const encryptedVault = await encryptData(JSON.stringify(vault), password);
        
        if (!encryptedVault) {
            alert('Error creating your secure vault');
            return;
        }
        
        // Create new user (store only email and encrypted vault)
        const newUser = {
            id: Date.now().toString(),
            name,
            email,
            encryptedVault,
            createdAt: new Date().toISOString()
        };
        
        // Save user (without storing plaintext password)
        users.push(newUser);
        localStorage.setItem('users', JSON.stringify(users));
        
        // Auto-login
        localStorage.setItem('isLoggedIn', 'true');
        localStorage.setItem('currentUser', JSON.stringify({
            id: newUser.id,
            name: newUser.name,
            email: newUser.email
        }));
        localStorage.setItem('currentPassword', password);
        window.location.href = 'home.html';
    });
}

// Logout functionality
const logoutBtn = document.querySelector('.logout');
if (logoutBtn) {
    logoutBtn.addEventListener('click', function(e) {
        e.preventDefault();
        localStorage.removeItem('isLoggedIn');
        localStorage.removeItem('currentUser');
        localStorage.removeItem('currentPassword');
        window.location.href = 'index.html';
    });
}

// Display current user in dashboard
const userProfile = document.querySelector('.user-profile span');
if (userProfile) {
    const currentUser = JSON.parse(localStorage.getItem('currentUser'));
    if (currentUser) {
        userProfile.textContent = currentUser.name;
        
        // Update welcome message
        const welcomeHeading = document.querySelector('.welcome-banner h1');
        if (welcomeHeading) {
            welcomeHeading.textContent = `Welcome back, ${currentUser.name}`;
        }
    }
}

// Initialize the application
document.addEventListener('DOMContentLoaded', function() {
    // Toggle password visibility
    const togglePasswordButtons = document.querySelectorAll('.toggle-password');
    
    togglePasswordButtons.forEach(button => {
        button.addEventListener('click', function() {
            const input = this.parentElement.querySelector('input');
            const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
            input.setAttribute('type', type);
            
            // Toggle icon
            this.classList.toggle('fa-eye');
            this.classList.toggle('fa-eye-slash');
        });
    });
    
    // Password strength indicator (for signup page)
    const passwordInput = document.getElementById('password');
    if (passwordInput) {
        passwordInput.addEventListener('input', function() {
            const strengthBars = document.querySelectorAll('.strength-bar');
            const password = this.value;
            
            // Reset bars
            strengthBars.forEach(bar => {
                bar.style.backgroundColor = '#e1e5eb';
            });
            
            // Very weak
            if (password.length > 0) {
                strengthBars[0].style.backgroundColor = '#ef233c';
            }
            
            // Weak
            if (password.length >= 6) {
                strengthBars[1].style.backgroundColor = '#ff9f1c';
            }
            
            // Medium
            if (password.length >= 8 && /[A-Z]/.test(password) && /[0-9]/.test(password)) {
                strengthBars[1].style.backgroundColor = '#2ec4b6';
                strengthBars[2].style.backgroundColor = '#2ec4b6';
            }
            
            // Strong
            if (password.length >= 10 && /[A-Z]/.test(password) && /[0-9]/.test(password) && /[^A-Za-z0-9]/.test(password)) {
                strengthBars[2].style.backgroundColor = '#4361ee';
            }
        });
    }
    
    // Check authentication status
    checkAuth();
    
    // Initialize password management if on home page
    if (window.location.pathname.endsWith('home.html')) {
        initPasswordManagement();
        displayPasswords();
    }
});