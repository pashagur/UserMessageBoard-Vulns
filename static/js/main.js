document.addEventListener('DOMContentLoaded', function() {
    // Function to handle message deletion with confirmation
    const setupMessageDeletion = () => {
        const deleteButtons = document.querySelectorAll('.delete-message');
        deleteButtons.forEach(button => {
            button.addEventListener('click', function(e) {
                e.preventDefault();
                if (confirm('Are you sure you want to delete this message?')) {
                    const form = this.closest('form');
                    form.submit();
                }
            });
        });
    };

    // Function to show password requirements on registration form
    const setupPasswordRequirements = () => {
        const passwordField = document.getElementById('password');
        if (passwordField) {
            const requirementsDiv = document.createElement('div');
            requirementsDiv.className = 'password-requirements small text-muted mt-1';
            requirementsDiv.innerHTML = 'Password must be at least 8 characters long.';
            passwordField.parentNode.appendChild(requirementsDiv);
        }
    };

    // Function to handle form validation feedback
    const setupFormValidation = () => {
        const forms = document.querySelectorAll('.needs-validation');
        
        Array.from(forms).forEach(form => {
            form.addEventListener('submit', event => {
                if (!form.checkValidity()) {
                    event.preventDefault();
                    event.stopPropagation();
                }
                form.classList.add('was-validated');
            }, false);
        });
    };

    // Function to add timestamp tooltips
    const setupTimestamps = () => {
        const timestamps = document.querySelectorAll('.message-timestamp');
        timestamps.forEach(timestamp => {
            const datetime = new Date(timestamp.getAttribute('data-timestamp'));
            const formattedDate = datetime.toLocaleString();
            timestamp.setAttribute('title', formattedDate);
        });
    };

    // Function to limit message length
    const setupMessageLengthCounter = () => {
        const messageContent = document.getElementById('content');
        if (messageContent) {
            const maxLength = 500;
            const counter = document.createElement('div');
            counter.className = 'message-counter small text-muted mt-1';
            counter.innerHTML = `0/${maxLength} characters`;
            messageContent.parentNode.appendChild(counter);

            messageContent.addEventListener('input', function() {
                const charCount = this.value.length;
                counter.innerHTML = `${charCount}/${maxLength} characters`;
                
                if (charCount > maxLength) {
                    counter.classList.add('text-danger');
                } else {
                    counter.classList.remove('text-danger');
                }
            });
        }
    };

    // Initialize all functions
    setupMessageDeletion();
    setupPasswordRequirements();
    setupFormValidation();
    setupTimestamps();
    setupMessageLengthCounter();

    // Handle flash messages auto-dismiss
    const flashMessages = document.querySelectorAll('.alert-dismissible');
    flashMessages.forEach(flash => {
        setTimeout(() => {
            const closeButton = flash.querySelector('.btn-close');
            if (closeButton) {
                closeButton.click();
            }
        }, 5000); // Auto-dismiss after 5 seconds
    });
});
