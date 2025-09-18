// Main JavaScript file for VeilGuard
document.addEventListener('DOMContentLoaded', function() {
    // Initialize common functionality
    initializeNavigation();
    initializeNotifications();
});

function initializeNavigation() {
    // Handle logout button
    const logoutBtn = document.querySelector('.logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', async (e) => {
            e.preventDefault();
            
            try {
                const response = await fetch('/api/v1/auth/logout', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    }
                });
                
                if (response.ok) {
                    window.location.href = '/';
                } else {
                    console.error('Logout failed');
                }
            } catch (error) {
                console.error('Logout error:', error);
            }
        });
    }
}

function initializeNotifications() {
    // Auto-hide notifications after 5 seconds
    const notifications = document.querySelectorAll('.notification:not(.hidden)');
    notifications.forEach(notification => {
        setTimeout(() => {
            notification.classList.add('hidden');
        }, 5000);
    });
}

// Utility functions
function showNotification(message, type = 'info') {
    const notification = document.getElementById('notification');
    const messageElement = document.getElementById('notificationMessage');
    
    if (notification && messageElement) {
        messageElement.textContent = message;
        notification.className = `notification ${type}`;
        
        setTimeout(() => {
            notification.classList.add('hidden');
        }, 5000);
    }
}

function hideNotification() {
    const notification = document.getElementById('notification');
    if (notification) {
        notification.classList.add('hidden');
    }
}

// Form validation helpers
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

function validatePassword(password) {
    // At least 6 characters
    return password.length >= 6;
}

// API helpers
async function apiRequest(url, options = {}) {
    const defaultOptions = {
        headers: {
            'Content-Type': 'application/json',
        },
    };
    
    const mergedOptions = {
        ...defaultOptions,
        ...options,
        headers: {
            ...defaultOptions.headers,
            ...options.headers,
        },
    };
    
    try {
        const response = await fetch(url, mergedOptions);
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.message || 'Request failed');
        }
        
        return data;
    } catch (error) {
        console.error('API request failed:', error);
        throw error;
    }
}