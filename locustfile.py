from locust import HttpUser, task, between

class WebsiteUser(HttpUser):
    # This class defines the behavior of a single simulated user.

    # wait_time defines the minimum and maximum time a user will wait
    # between tasks, in seconds. This simulates a user's "think time."
    wait_time = between(5, 15)

    # @task is a decorator that tells Locust to execute this method.
    # The number in parentheses is the "weight" of the task. A higher
    # number means this task will be executed more often.
    @task
    def load_homepage(self):
        # This simulates a user loading the homepage of your Flask app.
        self.client.get("/")

    @task(3)
    def load_product_page(self):
        # This simulates a user Browse a product page.
        # It's more likely to be called than load_homepage because of its weight.
        # Replace '/product/123' with an actual product URL from your site.
        self.client.get("/product/123")
        
    @task(1)
    def checkout(self):
        # Simulates a user initiating a checkout process.
        # This is less likely to happen than Browse.
        self.client.post("/checkout", {"item_id": "123", "quantity": "1"})

    # The on_start method runs once for each user when they first "spawn."
    def on_start(self):
        # This could be used to simulate a login action, for example.
        # self.client.post("/login", {"username": "testuser", "password": "password"})
        pass