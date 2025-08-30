import re

def parse_query(query):
    query = query.lower()
    filters = {}

    # Basic categories
    if "jeans" in query:
        filters['category'] = "jeans"
    if "t-shirt" in query or "tshirt" in query or "tee" in query:
        filters['category'] = "t-shirt"
    if "shirt" in query:
        filters['category'] = "shirt"
    if "sneakers" in query or "shoes" in query:
        filters['category'] = "shoes"
    if "kurti" in query:
        filters['category'] = "kurti"

    # Gender
    if "men" in query or "male" in query:
        filters['gender'] = "male"
    if "women" in query or "female" in query:
        filters['gender'] = "female"

    # Price
    price_match = re.search(r"(?:under|below|less than)\s*₹?(\d+)", query)
    if price_match:
        filters['price_max'] = int(price_match.group(1))

    # Neck type, sleeve, size, etc.
    if "round neck" in query:
        filters['neck'] = "round"
    if "v-neck" in query or "v neck" in query:
        filters['neck'] = "v"
    if "full sleeve" in query:
        filters['sleeve'] = "full"
    if "half sleeve" in query:
        filters['sleeve'] = "half"
    if "size" in query:
        size_match = re.search(r"size\s*(\w+)", query)
        if size_match:
            filters['size'] = size_match.group(1).upper()

    return filters
