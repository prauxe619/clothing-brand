
    // Function to show custom modal messages
    function showModalMessage(message, type = 'error') {
        const modal = document.getElementById('messageModal');
        const modalMessage = document.getElementById('modalMessage');
        const modalCloseButton = document.getElementById('modalCloseButton');

        modalMessage.textContent = message;
        // You can add more styling here based on 'type' if needed
        if (type === 'error') {
            modalMessage.style.color = '#ef4444'; // Tailwind red-500
        } else {
            modalMessage.style.color = '#333'; // Default text color
        }

        modal.classList.add('show');

        modalCloseButton.onclick = () => {
            modal.classList.remove('show');
        };

        // Close modal if clicked outside (optional)
        modal.onclick = (event) => {
            if (event.target === modal) {
                modal.classList.remove('show');
            }
        };
    }

    document.addEventListener('DOMContentLoaded', () => {
        const sidebar = document.getElementById('sidebar');
        const openSidebarBtn = document.getElementById('openSidebar');
        const closeSidebarBtn = document.getElementById('closeSidebar');

        const mobileSearchOverlay = document.getElementById('mobileSearchOverlay');
        const openSearchBtn = document.getElementById('openSearch');
        const closeSearchBtn = document.getElementById('closeMobileSearch');

        openSidebarBtn.addEventListener('click', () => {
            sidebar.classList.remove('-translate-x-full');
        });

        closeSidebarBtn.addEventListener('click', () => {
            sidebar.classList.add('-translate-x-full');
        });

        // Check if openSearchBtn exists before adding event listener
        if (openSearchBtn) {
            openSearchBtn.addEventListener('click', () => {
                mobileSearchOverlay.classList.remove('hidden');
                document.getElementById('mobileSearchInput').focus();
            });
        }
        

        closeSearchBtn.addEventListener('click', () => {
            mobileSearchOverlay.classList.add('hidden');
        });
    });

        // --- Search Bar Toggle JS ---
        // Ensure openSearchBtn is correctly referenced or created if it's for mobile search toggle
        // If 'openSearch' is meant for the desktop search bar toggle, ensure it exists in your HTML.
        // Assuming 'openSearch' is for a mobile search toggle button that you might have elsewhere.
        // If it's not present, this part of the JS will not execute.
        const openSearchBtn = document.getElementById('openSearch'); // This might be undefined if not in HTML
        const searchForm = document.getElementById('searchForm');
        const searchInput = document.getElementById('searchInputDesktop'); // Changed to Desktop ID

        if (openSearchBtn) { // Only add listener if the button exists
            openSearchBtn.addEventListener('click', (event) => {
                event.stopPropagation(); // Prevent click from bubbling up to document and immediately closing
                searchForm.classList.toggle('hidden');
                searchForm.classList.toggle('flex'); // Ensure it displays as flex
                if (!searchForm.classList.contains('hidden')) {
                    searchInput.focus(); // Focus on the input when it appears
                }
            });
        }


        // Hide search bar when clicking outside on mobile
        document.addEventListener('click', (event) => {
            if (window.innerWidth < 768) { // Only apply on mobile (md breakpoint)
                const isClickInsideSearch = searchForm.contains(event.target) || (openSearchBtn && openSearchBtn.contains(event.target));
                // Assuming 'openBtn' is a typo and should refer to 'openSidebarBtn'
                const openSidebarBtnElement = document.getElementById('openSidebar');
                const isClickInsideSidebarToggle = openSidebarBtnElement && openSidebarBtnElement.contains(event.target); 

                // Close search if clicked outside search area AND not on sidebar toggle AND search is visible
                if (!isClickInsideSearch && !isClickInsideSidebarToggle && !searchForm.classList.contains('hidden')) {
                    searchForm.classList.add('hidden');
                    searchForm.classList.remove('flex');
                }
            }
        });

        // Prevent clicking inside the search form from closing it
        searchForm.addEventListener('click', (event) => {
            event.stopPropagation();
        });
    
        // Initialize wishlist hearts on page load for guests
        document.addEventListener('DOMContentLoaded', () => {
            if (!window.isAuthenticated) {
                const wishlist = JSON.parse(localStorage.getItem('wishlist')) || [];
                document.querySelectorAll('.wishlist-btn').forEach(button => {
                    const productId = button.dataset.productId;
                    const heart = button.querySelector('.heart');
                    if (wishlist.includes(productId)) {
                        heart.textContent = '❤️';
                        heart.className = 'heart text-pink-600';
                    } else {
                        heart.textContent = '🤍';
                        heart.className = 'heart text-gray-400';
                    }
                });
            }
        });

        // Wishlist toggle button click handler
        document.querySelectorAll('.wishlist-btn').forEach(button => {
            button.addEventListener('click', () => {
                const productId = button.dataset.productId;

                fetch(`/toggle-wishlist/${productId}`, { method: 'POST' })
                    .then(res => res.json())
                    .then(data => {
                        const heart = button.querySelector('.heart');

                        if (data.guest) {
                            // Guest user - update localStorage wishlist
                            let wishlist = JSON.parse(localStorage.getItem('wishlist')) || [];

                            if (wishlist.includes(productId)) {
                                wishlist = wishlist.filter(id => id !== productId);
                                heart.textContent = '🤍';
                                heart.className = 'heart text-gray-400';
                            } else {
                                wishlist.push(productId);
                                heart.textContent = '❤️';
                                heart.className = 'heart text-pink-600';
                            }

                            localStorage.setItem('wishlist', JSON.stringify(wishlist));

                        } else {
                            // Logged-in user - update heart from server response
                            heart.textContent = data.in_wishlist ? '❤️' : '🤍';
                            heart.className = data.in_wishlist ? 'heart text-pink-600' : 'heart text-gray-400';
                        }
                    })
                    .catch(() => {
                        showModalMessage("Error updating wishlist. Please try again.", 'error'); // Using custom modal
                    });
            });
        });
   
        // Renamed showToast to showFlashedMessage to avoid confusion with the new modal
        function showFlashedMessage(message, type = 'success') {
            const toast = document.createElement('div');
            toast.textContent = message;

            toast.className = `fixed top-5 right-5 px-4 py-2 rounded shadow z-50 transition-all duration-300 ${
                type === 'success' ? 'bg-green-100 text-green-800' :
                type === 'danger' ? 'bg-red-100 text-red-800' :
                'bg-gray-100 text-gray-800'
            }`;

            document.body.appendChild(toast);

            setTimeout(() => {
                toast.remove();
            }, 3000);
        }
  
document.addEventListener('DOMContentLoaded', () => {
  const modal = document.getElementById('exitIntentModal');
  const closeBtn = document.getElementById('exitModalClose');

  let shown = sessionStorage.getItem('exitIntentShown');
  const isDesktop = window.innerWidth > 768;

  function showModal() {
    modal.classList.remove('hidden');
    setTimeout(() => {
      modal.classList.add('opacity-100');
      modal.classList.remove('opacity-0');
    }, 10);
    sessionStorage.setItem('exitIntentShown', 'true');
  }

  function hideModal() {
    modal.classList.add('opacity-0');
    modal.classList.remove('opacity-100');
    setTimeout(() => modal.classList.add('hidden'), 300);
  }

  // Trigger only on desktop + once per session
  if (!shown && isDesktop) {
    document.addEventListener('mouseout', async (e) => {
      if (e.clientY <= 0 && e.relatedTarget == null) {
        try {
          const res = await fetch('/cart/preview');
          const data = await res.json();
          if (data.products.length > 0) {
            showModal();
          }
        } catch (err) {
          console.error('Cart check failed', err);
        }
      }
    });
  }

  closeBtn.addEventListener('click', hideModal);
});



<script src="https://cdn.jsdelivr.net/npm/swiper@11/swiper-bundle.min.js"></script>

  var swiper = new Swiper(".mySwiper", {
    loop: true,
    autoplay: {
      delay: 4000,
      disableOnInteraction: false,
    },
    pagination: {
      el: ".swiper-pagination",
      clickable: true,
    },
    navigation: {
      nextEl: ".swiper-button-next",
      prevEl: ".swiper-button-prev",
    },
  });

// Modified startVoiceSearch to accept input and mic icon IDs
function startVoiceSearch(searchInputId, micIconId) {
    const micIcon = document.getElementById(micIconId);
    const searchInput = document.getElementById(searchInputId);
    const form = searchInput.closest('form'); // Get the parent form of the input

    // Check for browser support
    if (!('webkitSpeechRecognition' in window)) {
        showModalMessage("Voice search not supported in this browser. Please use Chrome or Edge.", 'error');
        return;
    }

    const recognition = new webkitSpeechRecognition();
    recognition.lang = 'en-IN';  // Set language as needed
    recognition.interimResults = false;
    recognition.maxAlternatives = 1;

    // Visual feedback: Start recording
    micIcon.classList.add('recording');
    searchInput.placeholder = "Listening...";

    recognition.start();

    recognition.onresult = function(event) {
        const transcript = event.results[0][0].transcript;
        searchInput.value = transcript;
        searchInput.placeholder = "Search..."; // Reset placeholder
        micIcon.classList.remove('recording'); // Stop recording visual
        form.submit();  // auto-submit after speaking
    };

    recognition.onerror = function(event) {
        console.error('Speech recognition error:', event.error);
        let errorMessage = "Error recognizing voice. Please try again.";
        if (event.error === 'no-speech') {
            errorMessage = "No speech detected. Please speak clearly into your microphone.";
        } else if (event.error === 'not-allowed') {
            errorMessage = "Microphone access denied. Please allow microphone permissions in your browser settings.";
        } else if (event.error === 'aborted') {
            errorMessage = "Voice search cancelled.";
        } else if (event.error === 'network') {
            errorMessage = "Network error during voice recognition. Check your internet connection.";
        }
        showModalMessage(errorMessage, 'error'); // Using custom modal
        searchInput.placeholder = "Search..."; // Reset placeholder
        micIcon.classList.remove('recording'); // Stop recording visual
    };

    recognition.onend = function() {
        // This fires when speech recognition stops (either by user stop, error, or silence)
        micIcon.classList.remove('recording'); // Ensure recording visual is off
        searchInput.placeholder = "Search..."; // Ensure placeholder is reset
    };
}

  const username = "{{ current_user.name }}"; // Flask user
  let hasGreeted = false;

  function toggleChatbot() {
    const chatbot = document.getElementById("chatbot");
    chatbot.classList.toggle("hidden");

    // Greet only once when chat is first opened
    if (!hasGreeted && !chatbot.classList.contains("hidden")) {
      setTimeout(() => {
        appendMessage("Bot", `Hi ${username}, how can I help you?`);
        showActionButtons();
        hasGreeted = true;
      }, 300);
    }
  }

  function handleUserInput(e) {
    e.preventDefault();
    const input = document.getElementById("chatInput");
    const message = input.value.trim();
    if (!message) return;

    appendMessage("You", message);
    input.value = "";

    if (["hi", "hello", "hey"].includes(message.toLowerCase())) {
      setTimeout(() => {
        appendMessage("Bot", `Hi ${username}, how can I help you?`);
        showActionButtons();
      }, 500);
    } else {
      fetch("/chatbot", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message })
      })
      .then(response => response.json())
      .then(data => appendMessage("Bot", data.reply))
      .catch(() => appendMessage("Bot", "Sorry, something went wrong."));
    }

    return false;
  }

  function appendMessage(sender, text) {
    const chatContent = document.getElementById("chatContent");
    const msg = document.createElement("div");

    // Create strong element for sender label
    const strong = document.createElement("strong");
    strong.textContent = sender === "You" ? "🗣️ You" : "🤖 Bot";
    msg.appendChild(strong);
    msg.appendChild(document.createElement("br"));

    // Split text by newline and append safely
    text.split("\n").forEach(line => {
        const textNode = document.createTextNode(line);
        msg.appendChild(textNode);
        msg.appendChild(document.createElement("br"));
    });

    // Add styling classes
    msg.className = sender === "You"
        ? "text-right text-black p-2"
        : "text-left text-gray-800 p-2 bg-gray-100 rounded";

    chatContent.appendChild(msg);
    chatContent.scrollTop = chatContent.scrollHeight;
}


  function showActionButtons() {
    const chatContent = document.getElementById("chatContent");

    const buttonsHTML = `
      <div class="space-y-2 mt-2">
        <button onclick="sendPredefined('Track my order')" class="w-full bg-pink-100 text-pink-800 px-4 py-2 rounded-full text-left">📦 Track Order</button>
        <button onclick="sendPredefined('Cancel an item')" class="w-full bg-red-100 text-red-800 px-4 py-2 rounded-full text-left">❌ Cancel Order</button>
        <button onclick="sendPredefined('Contact customer support')" class="w-full bg-yellow-100 text-yellow-800 px-4 py-2 rounded-full text-left">🧑‍💼 Contact Support</button>
      </div>
    `;

    const wrapper = document.createElement("div");
    wrapper.innerHTML = buttonsHTML;
    chatContent.appendChild(wrapper);
    chatContent.scrollTop = chatContent.scrollHeight;
  }

  function sendPredefined(msg) {
    appendMessage("You", msg);

    // Simple static responses (can be removed if GPT should handle it)
    let botResponse = "";
    if (msg.includes("Track")) {
      botResponse = "Please enter your order ID to track your order.";
    } else if (msg.includes("Cancel")) {
      botResponse = "Please provide the item/order you wish to cancel.";
    } else if (msg.includes("Contact")) {
    botResponse = `
      You can contact us here:
      📧 Email: connect@prauxe.com
      📞 Phone: +91-9999999999
      We're available 9AM to 6PM, Monday to Saturday.
    `;
  }

  setTimeout(() => appendMessage("Bot", botResponse), 500);
}

let orderOffset = 0;
const orderLimit = 3;

function loadOrders(offset=0) {
  fetch(`/api/user/orders?limit=${orderLimit}&offset=${offset}`)
    .then(res => res.json())
    .then(data => {
      if (data.orders.length === 0 && offset === 0) {
        showMessage("No orders found.");
        return;
      }
      
      data.orders.forEach(order => {
        showMessage(`Order #${order.order_id} - ${order.date} - Status: ${order.status}`);
      });

      if (data.orders.length === orderLimit) {
        showButton("Show more orders", () => {
          orderOffset += orderLimit;
          loadOrders(orderOffset);
        });
      }
    });
}

// When user clicks "Track Order"
function onTrackOrderSelected() {
  orderOffset = 0;
  loadOrders(orderOffset);
}