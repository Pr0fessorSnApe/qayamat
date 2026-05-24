from .base import ToolWrapper

class GowitnessWrapper(ToolWrapper):
    name = "gowitness"
    def screenshot_file(self, url_file: str, output_dir: str = "data/screenshots") -> str:
        return self.run(["scan", "file", "-f", url_file, "--screenshot-path", output_dir], timeout=300)
