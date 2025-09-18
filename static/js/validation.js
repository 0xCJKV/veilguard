// Client-side validation for HTMX forms
class FormValidator {
    constructor() {
        this.initializeValidation();
    }

    initializeValidation() {
        // Listen for HTMX events
        document.addEventListener('htmx:beforeRequest', (event) => {
            this.clearValidationErrors(event.target);
        });

        document.addEventListener('htmx:afterRequest', (event) => {
            if (event.detail.xhr.status === 422) {
                // Validation error response
                this.handleValidationResponse(event.target, event.detail.xhr.responseText);
            }
        });

        // Real-time validation on input
        document.addEventListener('input', (event) => {
            if (event.target.matches('input[data-validate], textarea[data-validate]')) {
                this.validateField(event.target);
            }
        });

        // Validation on blur for better UX
        document.addEventListener('blur', (event) => {
            if (event.target.matches('input[data-validate], textarea[data-validate]')) {
                this.validateField(event.target);
            }
        }, true);
    }

    validateField(field) {
        const value = field.value.trim();
        const fieldName = field.name;
        const validationType = field.dataset.validate;

        this.clearFieldError(field);

        let isValid = true;
        let errorMessage = '';

        switch (validationType) {
            case 'username':
                const usernameResult = this.validateUsername(value);
                isValid = usernameResult.isValid;
                errorMessage = usernameResult.message;
                break;
            case 'email':
                const emailResult = this.validateEmail(value);
                isValid = emailResult.isValid;
                errorMessage = emailResult.message;
                break;
            case 'password':
                const passwordResult = this.validatePassword(value);
                isValid = passwordResult.isValid;
                errorMessage = passwordResult.message;
                break;
            case 'required':
                if (!value) {
                    isValid = false;
                    errorMessage = 'This field is required';
                }
                break;
        }

        if (!isValid) {
            this.showFieldError(field, errorMessage);
        }

        return isValid;
    }

    validateUsername(username) {
        if (!username) {
            return { isValid: false, message: 'Username is required' };
        }
        if (username.length < 3) {
            return { isValid: false, message: 'Username must be at least 3 characters long' };
        }
        if (username.length > 50) {
            return { isValid: false, message: 'Username must not exceed 50 characters' };
        }
        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            return { isValid: false, message: 'Username can only contain letters, numbers, and underscores' };
        }
        return { isValid: true, message: '' };
    }

    validateEmail(email) {
        if (!email) {
            return { isValid: false, message: 'Email is required' };
        }
        const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        if (!emailRegex.test(email)) {
            return { isValid: false, message: 'Please enter a valid email address' };
        }
        if (email.length > 254) {
            return { isValid: false, message: 'Email address is too long' };
        }
        return { isValid: true, message: '' };
    }

    validatePassword(password) {
        if (!password) {
            return { isValid: false, message: 'Password is required' };
        }
        if (password.length < 8) {
            return { isValid: false, message: 'Password must be at least 8 characters long' };
        }
        if (password.length > 128) {
            return { isValid: false, message: 'Password must not exceed 128 characters' };
        }
        if (!/[a-z]/.test(password)) {
            return { isValid: false, message: 'Password must contain at least one lowercase letter' };
        }
        if (!/[A-Z]/.test(password)) {
            return { isValid: false, message: 'Password must contain at least one uppercase letter' };
        }
        if (!/\d/.test(password)) {
            return { isValid: false, message: 'Password must contain at least one number' };
        }
        if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
            return { isValid: false, message: 'Password must contain at least one special character' };
        }
        return { isValid: true, message: '' };
    }

    showFieldError(field, message) {
        // Add error class to field
        field.classList.add('error');
        
        // Create or update error message
        let errorElement = field.parentNode.querySelector('.field-error');
        if (!errorElement) {
            errorElement = document.createElement('div');
            errorElement.className = 'field-error';
            field.parentNode.appendChild(errorElement);
        }
        errorElement.textContent = message;
        errorElement.style.display = 'block';
    }

    clearFieldError(field) {
        field.classList.remove('error');
        const errorElement = field.parentNode.querySelector('.field-error');
        if (errorElement) {
            errorElement.style.display = 'none';
        }
    }

    clearValidationErrors(form) {
        const errorFields = form.querySelectorAll('.error');
        errorFields.forEach(field => {
            this.clearFieldError(field);
        });

        // Clear any existing validation error containers
        const errorContainers = form.querySelectorAll('.validation-errors');
        errorContainers.forEach(container => {
            container.remove();
        });
    }

    handleValidationResponse(form, responseText) {
        // Insert the validation errors HTML into the form
        const errorContainer = document.createElement('div');
        errorContainer.innerHTML = responseText;
        
        // Insert at the top of the form
        form.insertBefore(errorContainer.firstElementChild, form.firstChild);
    }
}

// Initialize validation when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    new FormValidator();
});

// Rate limiting for form submissions
class RateLimiter {
    constructor() {
        this.submissions = new Map();
        this.maxSubmissions = 5; // Max submissions per minute
        this.timeWindow = 60000; // 1 minute in milliseconds
    }

    canSubmit(formId) {
        const now = Date.now();
        const submissions = this.submissions.get(formId) || [];
        
        // Remove old submissions outside the time window
        const recentSubmissions = submissions.filter(time => now - time < this.timeWindow);
        
        if (recentSubmissions.length >= this.maxSubmissions) {
            return false;
        }
        
        // Record this submission
        recentSubmissions.push(now);
        this.submissions.set(formId, recentSubmissions);
        
        return true;
    }

    getTimeUntilNextSubmission(formId) {
        const submissions = this.submissions.get(formId) || [];
        if (submissions.length === 0) return 0;
        
        const oldestSubmission = Math.min(...submissions);
        const timeUntilReset = this.timeWindow - (Date.now() - oldestSubmission);
        
        return Math.max(0, timeUntilReset);
    }
}

const rateLimiter = new RateLimiter();

// Add rate limiting to HTMX forms
document.addEventListener('htmx:beforeRequest', (event) => {
    const form = event.target.closest('form');
    if (!form) return;
    
    const formId = form.id || form.action || 'default';
    
    if (!rateLimiter.canSubmit(formId)) {
        event.preventDefault();
        const timeUntilNext = rateLimiter.getTimeUntilNextSubmission(formId);
        const seconds = Math.ceil(timeUntilNext / 1000);
        
        // Show rate limit message
        const message = `Too many requests. Please wait ${seconds} seconds before trying again.`;
        const errorContainer = document.createElement('div');
        errorContainer.className = 'validation-errors';
        errorContainer.innerHTML = `
            <div class="error-message rate-limit">
                <span class="error-icon">⚠️</span>
                ${message}
            </div>
        `;
        
        form.insertBefore(errorContainer, form.firstChild);
        
        // Remove the message after the timeout
        setTimeout(() => {
            errorContainer.remove();
        }, timeUntilNext);
    }
});