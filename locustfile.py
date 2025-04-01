from locust import HttpUser, task, between

class LinkShortenerUser(HttpUser):
    wait_time = between(1, 3)

    @task
    def create_link(self):
        self.client.post("/links/shorten", params={"original_url": "https://example.com"})
