document.addEventListener('DOMContentLoaded', function() {

    // --- Image Slider Logic (No changes needed) ---
    const sliderTrack = document.getElementById('slider-track');
    const slides = sliderTrack ? sliderTrack.querySelectorAll('img') : [];
    const prevSlideBtn = document.getElementById('prev-slide');
    const nextSlideBtn = document.getElementById('next-slide');
    const thumbnails = document.querySelectorAll('.thumbnail');
    const sliderIndicatorsContainer = document.getElementById('slider-indicators');

    let currentSlideIndex = 0;
    let slideWidth = 0;

    function updateSliderPosition() {
        if (sliderTrack && slides.length > 0) {
            sliderTrack.style.transform = `translateX(-${currentSlideIndex * slideWidth}px)`;
            updateActiveThumbnailAndIndicator();
        }
    }

    function goToSlide(index) {
        if (index >= 0 && index < slides.length) {
            currentSlideIndex = index;
            updateSliderPosition();
        }
    }

    function showNextSlide() {
        goToSlide((currentSlideIndex + 1) % slides.length);
    }

    function showPrevSlide() {
        goToSlide((currentSlideIndex - 1 + slides.length) % slides.length);
    }

    function updateActiveThumbnailAndIndicator() {
        thumbnails.forEach((thumb, index) => {
            if (parseInt(thumb.dataset.slideIndex) === currentSlideIndex) {
                thumb.classList.add('border-pink-600', 'active-thumbnail');
                thumb.classList.remove('border-transparent');
            } else {
                thumb.classList.remove('border-pink-600', 'active-thumbnail');
                thumb.classList.add('border-transparent');
            }
        });

        if (sliderIndicatorsContainer) {
            const dots = sliderIndicatorsContainer.querySelectorAll('.slider-dot');
            dots.forEach((dot, index) => {
                if (index === currentSlideIndex) {
                    dot.classList.add('bg-pink-600');
                    dot.classList.remove('bg-gray-300');
                } else {
                    dot.classList.remove('bg-pink-600');
                    dot.classList.add('bg-gray-300');
                }
            });
        }
    }

    if (sliderTrack && slides.length > 0) {
        window.addEventListener('load', () => {
            slideWidth = slides[0].offsetWidth;
            updateSliderPosition();
        });

        if (sliderIndicatorsContainer) {
            sliderIndicatorsContainer.innerHTML = '';
            slides.forEach((_, index) => {
                const dot = document.createElement('span');
                dot.classList.add('w-3', 'h-3', 'rounded-full', 'cursor-pointer', 'transition', 'slider-dot');
                dot.classList.add(index === 0 ? 'bg-pink-600' : 'bg-gray-300');
                dot.addEventListener('click', () => goToSlide(index));
                sliderIndicatorsContainer.appendChild(dot);
            });
        }

        if (prevSlideBtn) prevSlideBtn.addEventListener('click', showPrevSlide);
        if (nextSlideBtn) nextSlideBtn.addEventListener('click', showNextSlide);

        thumbnails.forEach(thumbnail => {
            thumbnail.addEventListener('click', function() {
                const index = parseInt(this.dataset.slideIndex);
                goToSlide(index);
            });
        });

        let touchStartX = 0;
        let touchEndX = 0;

        if (sliderTrack) {
            sliderTrack.addEventListener('touchstart', (e) => {
                touchStartX = e.touches[0].clientX;
            });

            sliderTrack.addEventListener('touchmove', (e) => {
                touchEndX = e.touches[0].clientX;
            });

            sliderTrack.addEventListener('touchend', () => {
                if (touchStartX - touchEndX > 50) {
                    showNextSlide();
                } else if (touchEndX - touchStartX > 50) {
                    showPrevSlide();
                }
                touchStartX = 0;
                touchEndX = 0;
            });
        }

        window.addEventListener('resize', () => {
            if (slides.length > 0) {
                slideWidth = slides[0].offsetWidth;
                updateSliderPosition();
            }
        });
    }

    // --- Share Product Modal Logic (No changes needed) ---
    // Elements (wire what exists; skip the rest)
const shareProductBtn    = document.getElementById('share-product-btn');    // the button you click
const shareProductModal  = document.getElementById('share-product-modal');  // modal wrapper
const closeShareModalBtn = document.getElementById('close-share-modal');    // X button
const shareLinkInput     = document.getElementById('share-link-input');     // input with URL
const copyLinkBtn        = document.getElementById('copy-link-btn');        // copy button
const copyStatus         = document.getElementById('copy-status');          // small “copied!” text
const shareIcons         = document.querySelectorAll('.share-icon');        // optional

const productUrl   = window.location.href;
const productTitle = document.title;

// Open / close helpers
function openShareModal() {
  if (!shareProductModal) return;
  shareProductModal.classList.remove('hidden');
  if (shareLinkInput) shareLinkInput.value = productUrl;
  buildShareLinks(); // safe even if no icons
}
function closeShareModal() {
  if (!shareProductModal) return;
  shareProductModal.classList.add('hidden');
  if (copyStatus) copyStatus.classList.add('hidden');
}

// Build social links only for icons that exist
function buildShareLinks() {
  if (!shareIcons || !shareIcons.length) return;
  shareIcons.forEach(icon => {
    const platform = icon.dataset.sharePlatform;
    let href = productUrl;
    switch (platform) {
      case 'facebook':
        href = `https://www.facebook.com/sharer/sharer.php?u=${encodeURIComponent(productUrl)}`;
        break;
      case 'twitter':
        href = `https://twitter.com/intent/tweet?url=${encodeURIComponent(productUrl)}&text=${encodeURIComponent('Check out this product from PRAUXE: ' + productTitle)}`;
        break;
      case 'whatsapp':
        href = `https://api.whatsapp.com/send?text=${encodeURIComponent(productTitle + ' ' + productUrl)}`;
        break;
      case 'pinterest':
        href = `https://pinterest.com/pin/create/button/?url=${encodeURIComponent(productUrl)}&description=${encodeURIComponent(productTitle)}`;
        break;
      case 'email':
        href = `mailto:?subject=${encodeURIComponent('Check this out!')}&body=${encodeURIComponent(productTitle + '\n\n' + productUrl)}`;
        break;
    }
    icon.href = href;
  });
}

// Wire the open action (even if no icons/copy elements exist)
if (shareProductBtn) {
  shareProductBtn.addEventListener('click', (e) => {
    e.preventDefault();
    openShareModal();
  });
}

// Close actions
if (closeShareModalBtn) closeShareModalBtn.addEventListener('click', closeShareModal);
if (shareProductModal) {
  shareProductModal.addEventListener('click', (e) => { if (e.target === shareProductModal) closeShareModal(); });
}
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && shareProductModal && !shareProductModal.classList.contains('hidden')) {
    closeShareModal();
  }
});

// Copy button (optional)
if (copyLinkBtn && shareLinkInput) {
  copyLinkBtn.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(shareLinkInput.value);
      if (copyStatus) {
        copyStatus.textContent = 'Link copied!';
        copyStatus.classList.remove('hidden');
        setTimeout(() => copyStatus.classList.add('hidden'), 2000);
      }
    } catch {
      // fallback
      shareLinkInput.select();
      document.execCommand('copy');
      if (copyStatus) {
        copyStatus.textContent = 'Copied! (Fallback)';
        copyStatus.classList.remove('hidden');
        setTimeout(() => copyStatus.classList.add('hidden'), 2000);
      }
    }
  });
}


    // --- Pincode Check Logic (No changes needed) ---
    const pincodeInput = document.getElementById('pincode-input');
    const checkPincodeBtn = document.getElementById('check-pincode-btn');
    const pincodeStatus = document.getElementById('pincode-status');

    if (pincodeInput && checkPincodeBtn && pincodeStatus) {
        checkPincodeBtn.addEventListener('click', function() {
            const pincode = pincodeInput.value;
            pincodeStatus.textContent = 'Checking availability...';
            pincodeStatus.classList.remove('text-green-600', 'text-red-500'); 

            if (pincode.length !== 6 || !/^\d+$/.test(pincode)) {
                pincodeStatus.textContent = 'Incorrect pincode. Enter a valid 6-digit pincode.';
                pincodeStatus.classList.add('text-red-500');
                return;
            }

            fetch('/check_pincode_serviceability', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').getAttribute('content') 
                },
                body: JSON.stringify({ pincode: pincode })
            })
            .then(response => {
                if (!response.ok) {
                    return response.json().then(errorData => {
                        throw new Error(errorData.message || `Server error: ${response.status}`);
                    }).catch(() => {
                        throw new Error(`Server error: ${response.status}`);
                    });
                }
                return response.json();
            })
            .then(data => {
                if (data.serviceable) {
                    const deliveryTime = data.delivery_time ? ` (expected in ${data.delivery_time} days)` : ' (expected in 3-5 days)';
                    pincodeStatus.textContent = `We will deliver here!${deliveryTime}`;
                    pincodeStatus.classList.remove('text-red-500');
                    pincodeStatus.classList.add('text-green-600');
                } else {
                    pincodeStatus.textContent = data.message || 'Currently not serviceable, will come to you soon!';
                    pincodeStatus.classList.remove('text-green-600');
                    pincodeStatus.classList.add('text-red-500');
                }
            })
            .catch(error => {
                console.error('Error checking pincode:', error);
                pincodeStatus.textContent = `Error: ${error.message}`;
                pincodeStatus.classList.remove('text-green-600');
                pincodeStatus.classList.add('text-red-500');
            });
        });
    }
    
    // --- Size Selection Logic (Updated to enforce stock + update hidden input) ---
const sizeOptions = document.querySelectorAll('.size-option');
if (sizeOptions.length > 0) {
    sizeOptions.forEach(button => {
        button.addEventListener('click', function() {
            // Reset all buttons
            sizeOptions.forEach(btn => {
                btn.classList.remove('bg-pink-600', 'text-white', 'hover:bg-pink-700');
                btn.classList.add('bg-gray-100', 'text-gray-800', 'hover:border-pink-600', 'hover:bg-pink-50', 'hover:text-pink-600');
            });

            // Activate clicked
            this.classList.add('bg-pink-600', 'text-white', 'hover:bg-pink-700');
            this.classList.remove('bg-gray-100', 'text-gray-800', 'hover:border-pink-600', 'hover:bg-pink-50', 'hover:text-pink-600');

            // --- Enforce stock quantity ---
            const maxQty = parseInt(this.dataset.max);
            const productQuantityInput = document.getElementById('product-quantity');
            if (productQuantityInput) {
                productQuantityInput.max = maxQty;
                if (parseInt(productQuantityInput.value) > maxQty) {
                    productQuantityInput.value = maxQty;
                }
            }

            // ✅ Update hidden input so form knows which size was picked
            const hiddenSizeInput = document.getElementById('selected-size');
            if (hiddenSizeInput) {
                hiddenSizeInput.value = this.dataset.size;
            }

            // ✅ (Optional) Show stock message below
            const stockMessage = document.getElementById("stock-message");
            if (stockMessage) {
                if (maxQty === 0) {
                    stockMessage.textContent = "Out of Stock";
                    stockMessage.className = "mt-2 text-sm font-medium text-red-600";
                } else if (maxQty <= 3) {
                    stockMessage.textContent = `Only ${maxQty} left!`;
                    stockMessage.className = "mt-2 text-sm font-medium text-red-500";
                } else {
                    stockMessage.textContent = "In Stock";
                    stockMessage.className = "mt-2 text-sm font-medium text-green-600";
                }
            }
        });
    });
}



    // --- ---- COLOR SELECTION: new minimal wiring ----
    const colorButtons = document.querySelectorAll('.color-option');
    const selectedColorInput = document.getElementById('selected-color'); // hidden input present in template
    const colorError = document.getElementById('color-error');

    if (colorButtons && colorButtons.length > 0) {
        colorButtons.forEach(btn => {
            btn.addEventListener('click', () => {
                // remove active ring from all and add to clicked
                colorButtons.forEach(b => b.classList.remove('ring-2', 'ring-black-500'));
                btn.classList.add('ring-2', 'ring-black-500');
                // set hidden input value so backend can read it
                if (selectedColorInput) selectedColorInput.value = btn.dataset.color || '';
                if (colorError) colorError.classList.add('hidden');
            });
        });
    }

    // --- Quantity Control Logic (No changes needed) ---
    const decreaseQtyBtn = document.getElementById('decrease-qty');
    const increaseQtyBtn = document.getElementById('increase-qty');
    const productQuantityInput = document.getElementById('product-quantity');
    const addToBagBtn = document.getElementById('add-to-bag-btn');

    if (decreaseQtyBtn && increaseQtyBtn && productQuantityInput) {
        function updateQuantity(delta) {
            let currentQty = parseInt(productQuantityInput.value);
            let newQty = currentQty + delta;
            let maxQty = parseInt(productQuantityInput.max);

            if (newQty < 1) newQty = 1;
            if (newQty > maxQty) newQty = maxQty;

            productQuantityInput.value = newQty;

            if (addToBagBtn) {
                if (newQty > 0 && newQty <= maxQty) {
                    addToBagBtn.classList.remove('opacity-50', 'cursor-not-allowed');
                    addToBagBtn.disabled = false;
                } else {
                    addToBagBtn.classList.add('opacity-50', 'cursor-not-allowed');
                    addToBagBtn.disabled = true;
                }
            }
        }

        decreaseQtyBtn.addEventListener('click', () => updateQuantity(-1));
        increaseQtyBtn.addEventListener('click', () => updateQuantity(1));

        productQuantityInput.addEventListener('change', function() {
            let val = parseInt(this.value);
            let maxQty = parseInt(this.max);
            if (isNaN(val) || val < 1) {
                this.value = 1;
            } else if (val > maxQty) {
                this.value = maxQty;
            }
            updateQuantity(0);
        });
    }

    // --- Add to Bag Button Logic (Corrected and final version) ---
    if (addToBagBtn) {
        addToBagBtn.addEventListener('click', function() {
            const productId = this.dataset.productId;
            const selectedSize = document.querySelector('.size-option.bg-pink-600');
            const quantity = parseInt(productQuantityInput.value);
            const csrfToken = document.querySelector('meta[name="csrf-token"]').getAttribute('content');

            // enforce size (existing behavior)
            if (!selectedSize) {
                alert('Please select a size before adding to bag.');
                return;
            }

            // enforce color if colors exist on page
            if (colorButtons && colorButtons.length > 0) {
                const colorVal = selectedColorInput ? selectedColorInput.value : '';
                if (!colorVal) {
                    // show user error (do not proceed)
                    if (colorError) {
                        colorError.classList.remove('hidden');
                        colorError.textContent = 'Please select a color.';
                        // scroll to error if needed
                        colorError.scrollIntoView({ behavior: 'smooth', block: 'center' });
                    } else {
                        alert('Please select a color.');
                    }
                    return;
                }
            }

            const sizeName = selectedSize.dataset.size;
            const colorName = selectedColorInput ? selectedColorInput.value : null;

            const productDetailsContainer = document.getElementById('product-details'); // Corrected ID
            const productName = productDetailsContainer.dataset.productName;
            const productPrice = parseFloat(productDetailsContainer.dataset.productPrice);
            const productCategory = productDetailsContainer.dataset.productCategory;
            
            fetch('/add_to_cart', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({
                    product_id: productId,
                    size: sizeName,
                    quantity: quantity,
                    color: colorName   // <-- included selected color
                }),
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    alert('Product added to bag!');
                    const bagCountSpan = document.getElementById('bag-item-count');
                    if (bagCountSpan) {
                        bagCountSpan.textContent = data.bag_count;
                    }
                    if (typeof gtag === 'function') {
                        gtag('event', 'add_to_cart', {
                            currency: 'INR',
                            value: productPrice * quantity,
                            items: [{
                                item_id: productId,
                                item_name: productName,
                                item_category: productCategory,
                                price: productPrice,
                                quantity: quantity
                            }]
                        });
                    }
                } else {
                    alert('Error adding product to bag: ' + data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('An error occurred while adding to bag.');
            });
        });
    }

    // --- Wishlist Button Logic (No changes needed) ---
    // --- Unified Wishlist Buttons Logic (handles main + similar/recent cards) ---
    (function() {
        const csrfTokenMeta = document.querySelector('meta[name="csrf-token"]');
        const csrfToken = csrfTokenMeta ? csrfTokenMeta.getAttribute('content') : null;
        if (!csrfToken) console.warn('CSRF token meta not found. Wishlist requests may fail.');

        // Select all wishlist buttons: both small ones and the main product button (if present)
        const wishlistButtons = Array.from(document.querySelectorAll('.wishlist-button'))
            // also include #add-to-wishlist-btn in case it doesn't have the class yet
            .concat(Array.from(document.querySelectorAll('#add-to-wishlist-btn')))
            // dedupe
            .filter((v, i, a) => a.indexOf(v) === i);

        if (wishlistButtons.length === 0) return;

        // Helper: read productId from element (supports data-product-id or data-id)
        function getProductIdFromElement(el) {
            return el.dataset.productId || el.dataset.id || null;
        }

        // Helper: update UI for a single button based on isInWishlist
        function renderButtonState(button, isInWishlist) {
            const icon = button.querySelector('i');
            const span = button.querySelector('span');
            const isMainBtn = button.id === 'add-to-wishlist-btn';

            // Icon class toggles (works for both .far (outline) and .fas (solid))
            if (icon) {
                icon.classList.remove('far', 'fas');
                icon.classList.add(isInWishlist ? 'fas' : 'far');
            }

            // If button has a textual span (main button), update text + styles
            if (span || isMainBtn) {
                // If no explicit span, try to find a text node or create one
                if (!span) {
                    // create a small span so we can update text consistently
                    const s = document.createElement('span');
                    s.style.display = 'none'; // keep hidden if you don't want text change
                    button.appendChild(s);
                }

                const textSpan = button.querySelector('span');
                if (textSpan) {
                    textSpan.textContent = isInWishlist ? 'WISHLISTED' : 'Wishlist';
                }

                // For the large main button, toggle the pink background classes
                if (isMainBtn) {
                    if (isInWishlist) {
                        button.classList.remove('border-gray-300', 'text-gray-700', 'hover:bg-pink-50', 'hover:border-pink-400');
                        button.classList.add('bg-pink-600', 'text-white', 'hover:bg-pink-700', 'hover:border-pink-600');
                    } else {
                        button.classList.remove('bg-pink-600', 'text-white', 'hover:bg-pink-700', 'hover:border-pink-600');
                        button.classList.add('border-gray-300', 'text-gray-700', 'hover:bg-pink-50', 'hover:border-pink-400');
                    }
                }
            }
        }

        // Initialize state for each button
        const stateByButton = new Map(); // button -> {productId, isInWishlist}
        wishlistButtons.forEach(button => {
            const productId = getProductIdFromElement(button);
            if (!productId) return; // skip invalid
            // initial state: prefer explicit data attribute, otherwise infer from icon class
            const explicit = button.dataset.initialWishlistStatus;
            const icon = button.querySelector('i');
            const inferred = icon ? icon.classList.contains('fas') : false;
            const isInWishlist = explicit === undefined ? inferred : (explicit === 'true');

            stateByButton.set(button, { productId, isInWishlist });
            renderButtonState(button, isInWishlist);
        });

        // Sync helper: update all buttons that match a productId
        function syncButtonsForProduct(productId, newState) {
            for (const [button, info] of stateByButton.entries()) {
                if (String(info.productId) === String(productId)) {
                    info.isInWishlist = newState;
                    renderButtonState(button, newState);
                }
            }
        }

        // Click handler
        wishlistButtons.forEach(button => {
            if (!stateByButton.has(button)) return;

            button.addEventListener('click', function(event) {
                event.preventDefault();
                const info = stateByButton.get(button);
                const productId = info.productId;

                // optimistic UI (toggle immediately for snappiness)
                const optimisticNewState = !info.isInWishlist;
                syncButtonsForProduct(productId, optimisticNewState);

                // send request
                fetch(`/toggle-wishlist/${productId}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        ...(csrfToken ? { 'X-CSRFToken': csrfToken } : {})
                    },
                    body: JSON.stringify({})
                })
                .then(response => {
                    if (!response.ok) {
                        // attempt to parse server message for helpful error
                        return response.json().then(err => {
                            throw new Error(err.message || `HTTP ${response.status}`);
                        }).catch(() => {
                            throw new Error(`HTTP ${response.status}`);
                        });
                    }
                    return response.json();
                })
                .then(data => {
                    if (data && data.success) {
                        // server authoritative state (safer than optimistic)
                        const serverState = !!data.in_wishlist;
                        syncButtonsForProduct(productId, serverState);
                        // if server returns a message, you can show a toast here
                        console.log(data.message || (serverState ? 'Added to wishlist' : 'Removed from wishlist'));
                    } else {
                        // revert optimistic change if server says failure
                        const revertState = info.isInWishlist;
                        syncButtonsForProduct(productId, revertState);
                        alert('Error toggling wishlist: ' + (data && data.message ? data.message : 'Unknown error'));
                    }
                })
                .catch(err => {
                    // network or parse error -> revert optimistic UI and show error
                    syncButtonsForProduct(productId, info.isInWishlist);
                    console.error('Wishlist toggle failed:', err);
                    alert('Failed to update wishlist: ' + err.message);
                });
            });
        });
    })();

    // --- Size Chart Modal Logic (No changes needed) ---
    const sizeChartTrigger = document.getElementById('size-chart-trigger');
    const womenSizeChartModal = document.getElementById('women-size-chart-modal');
    const menSizeChartModal = document.getElementById('men-size-chart-modal');
    const closeSizeChartModals = document.querySelectorAll('.close-size-chart-modal');

    if (sizeChartTrigger && womenSizeChartModal && menSizeChartModal) {
        sizeChartTrigger.addEventListener('click', function() {
            const category = this.dataset.productCategory;
            if (category === 'women' || category === "women's") {
                womenSizeChartModal.classList.remove('hidden');
            } else if (category === 'men' || category === "men's") {
                menSizeChartModal.classList.remove('hidden');
            }
        });

        closeSizeChartModals.forEach(button => {
            button.addEventListener('click', function() {
                womenSizeChartModal.classList.add('hidden');
                menSizeChartModal.classList.add('hidden');
            });
        });

        womenSizeChartModal.addEventListener('click', function(event) {
            if (event.target === womenSizeChartModal) {
                womenSizeChartModal.classList.add('hidden');
            }
        });

        menSizeChartModal.addEventListener('click', function(event) {
            if (event.target === menSizeChartModal) {
                menSizeChartModal.classList.add('hidden');
            }
        });

        document.addEventListener('keydown', function(event) {
            if (event.key === 'Escape') {
                womenSizeChartModal.classList.add('hidden');
                menSizeChartModal.classList.add('hidden');
            }
        });
    }

    // --- Recently Viewed Logic (No changes needed) ---
    const productDetailsElement = document.getElementById('product-details');
    if (productDetailsElement) {
        const productId = productDetailsElement.dataset.productId;
        const productName = productDetailsElement.dataset.productName;
        const productPrice = productDetailsElement.dataset.productPrice;
        const productImage = productDetailsElement.dataset.productImage;

        let recentlyViewed = JSON.parse(localStorage.getItem('recentlyViewed')) || [];
        recentlyViewed = recentlyViewed.filter(item => item.id !== productId);
        recentlyViewed.unshift({
            id: productId,
            name: productName,
            price: productPrice,
            image: productImage
        });

        if (recentlyViewed.length > 5) {
            recentlyViewed = recentlyViewed.slice(0, 5);
        }

        localStorage.setItem('recentlyViewed', JSON.stringify(recentlyViewed));
    }
});

document.addEventListener('DOMContentLoaded', function() {

  let selectedSize = null;
  let selectedColor = null;

  // --- Size selection ---
  const sizeButtons = document.querySelectorAll('.size-option');
  const stockMessage = document.getElementById('stock-message');
  const quantityInput = document.getElementById('product-quantity');

  sizeButtons.forEach(btn => {
    btn.addEventListener('click', function() {
      sizeButtons.forEach(b => b.classList.remove('bg-pink-600','text-white'));
      this.classList.add('bg-pink-600','text-white');

      selectedSize = this.dataset.size;
      const qty = parseInt(this.dataset.qty);

      // Show stock message
      if (qty === 0) {
        stockMessage.textContent = "Out of Stock";
        stockMessage.className = "mt-2 text-sm font-medium text-red-600";
      } else if (qty <= 3) {
        stockMessage.textContent = `Only ${qty} left!`;
        stockMessage.className = "mt-2 text-sm font-medium text-red-500";
      } else {
        stockMessage.textContent = "In Stock";
        stockMessage.className = "mt-2 text-sm font-medium text-green-600";
      }

      // Update max quantity
      quantityInput.max = qty;
      if (parseInt(quantityInput.value) > qty) quantityInput.value = qty;
    });
  });

  // --- Color selection ---
  const colorButtons = document.querySelectorAll('.color-option');
  colorButtons.forEach(btn => {
    btn.addEventListener('click', function() {
      colorButtons.forEach(b => b.classList.remove('ring-2','ring-black'));
      this.classList.add('ring-2','ring-black');
      selectedColor = this.dataset.color;
    });
  });

  // --- Add to Bag button ---
  document.getElementById('add-to-bag-btn').addEventListener('click', function() {
    if (!selectedSize) { alert('Please select a size'); return; }
    if (!selectedColor) { alert('Please select a color'); return; }

    const productId = this.dataset.productId;
    const quantity = parseInt(quantityInput.value) || 1;

    const csrfToken = '{{ csrf_token() }}'; // Flask-WTF CSRF

    fetch('{{ url_for("add_to_cart") }}', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-CSRFToken': csrfToken
      },
      body: JSON.stringify({
        product_id: productId,
        size: selectedSize,
        color: selectedColor,
        quantity: quantity
      })
    })
    .then(res => res.json())
    .then(data => {
      alert(data.message);
      if (data.success) location.reload(); // optionally update cart count
    })
    .catch(err => console.error(err));
  });

});


