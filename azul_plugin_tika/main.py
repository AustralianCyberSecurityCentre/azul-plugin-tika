"""Analyse files with Apache Tika to detect and extract metadata and text."""

import logging
import os
import time
import traceback
from urllib.error import URLError

from azul_runner import (
    BinaryPlugin,
    Feature,
    FeatureType,
    FeatureValue,
    Filepath,
    Job,
    State,
    add_settings,
    cmdline_run,
)
from requests import ConnectionError
from tika import unpack

# PyTika is very noisy, set the level to only log CRITICAL errors
logging.getLogger("tika.tika").setLevel(logging.CRITICAL)


class AzulPluginTika(BinaryPlugin):
    """Analyse files with Apache Tika to detect and extract metadata and text."""

    CONTACT = "ASD's ACSC"
    SETTINGS = add_settings(
        filter_data_types={"content": []},
        filter_max_content_size=(int, 20 * 1024 * 1024),  # File size to process
        max_text_size=(int, 10 * 1024 * 1024),  # Max text size before truncation
        tika_server=(str, "http://localhost:9998"),
        ignore_types=(
            list[str],
            [
                "application/vnd.android.package-archive",
                "application/java-archive",
                "application/x-archive",
            ],
        ),
    )
    VERSION = "2025.04.07"
    FEATURES = [
        # generic catch all feature
        Feature("file_metadata", "Metadata field extracted by tika, label is the field name", type=FeatureType.String),
        Feature("filename", "Attachment filename extracted from content", type=FeatureType.String),
        Feature("mime", "Magic mime type", type=FeatureType.String),
        Feature(
            "dropped_metadata",
            "Metadata that was too long so a sample was kept and the remainder dropped.",
            type=FeatureType.String,
        ),
    ]

    def execute(self, job: Job):
        """Submit the data to tika, mapping any extracted metadata/content into output."""
        data = job.get_data()
        # Providing file instead of buffer because there is a bug with tika 2.6 from_buffer method
        result = self.unpack(data.get_filepath())
        if not result:
            return State.Label.OPT_OUT

        features = {}
        # Print to gather data for unit tests.
        # print(f"METADATA FOR TEST WITH FILE WITH SHA256: {job.event.entity}")
        # print(result)
        if "metadata" in result:
            metadata = result["metadata"]
            # use and dump the 'Content-Type' field
            if "Content-Type" in metadata:
                # some file types we choose to ignore
                if metadata["Content-Type"] in self.cfg.ignore_types:
                    return State.Label.OPT_OUT
                elif isinstance(metadata["Content-Type"], str):
                    content_type = [metadata["Content-Type"]]
                else:
                    content_type = metadata["Content-Type"]
                features["mime"] = content_type
                del metadata["Content-Type"]

            # dump pointless metadata the 'Content-Length' 'Content-Encoding', 'X-Parsed-By' and 'resourceName'
            # Note: the metadata keys changes between versions so you'll need to keep checking back.
            for field in [
                "Content-Length",
                "Content-Encoding",
                "X-Parsed-By",
                "X-TIKA:Parsed-By",
                "X-TIKA:Parsed-By-Full-Set",
                "resourceName",
                "X-TIKA:EXCEPTION:embedded_stream_exception",  # Drop bad content from zip files
            ]:
                if field in metadata:
                    del metadata[field]

            # feature the remaining metadata
            for meta_key, meta_value in metadata.items():
                if isinstance(meta_value, str):
                    meta_value = [meta_value]
                for cur_meta_value in meta_value:
                    if not cur_meta_value:
                        continue
                    if len(cur_meta_value) > self.cfg.max_value_length:
                        # For content that is too long just take a sample of it.
                        features.setdefault("dropped_metadata", []).append(
                            FeatureValue(cur_meta_value[:100], label=meta_key)
                        )
                    else:
                        features.setdefault("file_metadata", []).append(FeatureValue(cur_meta_value, label=meta_key))

        # Set the text field as the returned plaintext content
        if "content" in result:
            content = result["content"].strip()
            if content:
                if len(content) > self.cfg.max_text_size:
                    content = content[: self.cfg.max_text_size] + "\n(truncated)"
                self.add_text(content)

        # Add any attachments as children entities
        if "attachments" in result:
            for child_name, child_data in result["attachments"].items():
                c = self.add_child_with_data({"action": "extracted"}, child_data)
                # sometimes it just uses the original file name, which is randomly generated
                if os.path.basename(data.get_filepath()) not in child_name:
                    c.add_feature_values("filename", Filepath(child_name))
        self.add_many_feature_values(features)

    def unpack(self, file_path: str):
        """Use the Tika server to unpack the given buffer.

        Provides limited retry on connection issues.
        """
        result = None
        try:
            result = unpack.from_file(file_path, self.cfg.tika_server, requestOptions={"timeout": 160})
        except TimeoutError:
            raise
        except ConnectionError:
            # sleep in-between each connection attempt
            self.logger.error(f"Warning issue contacting tika server with error {traceback.format_exc()}")
        except URLError:
            self.logger.error(f"Can't contact tika server with error {traceback.format_exc()}")
        except Exception:
            self.logger.error(traceback.format_exc())
            self.logger.warning("Unexpected error from tika retrying.")
        if result:
            return result
        time.sleep(1)
        # One more re-attempt or simply give the error.
        return unpack.from_file(file_path, self.cfg.tika_server, requestOptions={"timeout": 160})


def main():
    """Run plugin via command-line."""
    cmdline_run(plugin=AzulPluginTika)


if __name__ == "__main__":
    main()
