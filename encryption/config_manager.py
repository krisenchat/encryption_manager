import json
import os
import yaml

from google.cloud import secretmanager

region_pids = {"de": "data-warehouse-338012", "ua": "kc-data-warehouse-uaprod"}


def read_config_file():
    # Construct the config path
    base_dir = os.path.dirname(os.path.abspath(__file__))
    env = os.environ.get("ENVIRONMENT", "dev")
    config_path = os.path.join(base_dir, '../config', f'config_{env}.yml')

    with open(config_path) as file:
        config = yaml.load(file, Loader=yaml.FullLoader)

    return config


def get_models_to_load(config):
    model_names = []

    for region, region_models in config.items():
        for model, sizes in region_models.items():
            for size in sizes:
                # Formatting the string as per the required pattern
                model_name = f"{model}_{size}_{region}"
                model_names.append(model_name)

    return model_names


class ConfigManager:
    """Static class responsible for the handling of everything configuration related, such as google cloud dependencies,
    database connections, getting secrets from the SecretManager, loading google cloud credentials and loading
     configurations from the env specific yaml files"""

    @staticmethod
    def load_config():
        config = read_config_file()
        # models_to_load = get_models_to_load(config["models"])

        return config["credentials"], config["credentials"]["project_id"], bool(config["use_local_embeddings"])

        # Initialize class attributes by immediately calling load_config

    config, project_id, use_local_embeddings = load_config.__func__()
    credentials = None

    @staticmethod
    def get_secret(secret_id, version="latest", region=None):

        client = secretmanager.SecretManagerServiceClient()
        if ConfigManager.get_env() == "prd" and region:
            project_id = region_pids[region]
        else:
            project_id = ConfigManager.project_id

        secret_name = f"projects/{project_id}/secrets/{secret_id}/versions/{version}"
        response = client.access_secret_version(request={"name": secret_name})
        return response.payload.data.decode('UTF-8')

    @staticmethod
    def get_credentials_json_file(secret, filename):
        with open(filename, 'w') as f:
            f.write(json.dumps(json.loads(secret)))

    @staticmethod
    def connect_to_mlflow_server():
        credentials = ConfigManager.get_secret(secret_id="account_credentials")
        ConfigManager.get_credentials_json_file(credentials, "credentials.json")
        os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = "credentials.json"
        os.environ["MLFLOW_TRACKING_URI"] = ConfigManager.get_secret("mlflow_tracking_uri")
        os.environ["MLFLOW_TRACKING_USERNAME"] = ConfigManager.get_secret("mlflow_tracking_username")
        os.environ["MLFLOW_TRACKING_PASSWORD"] = ConfigManager.get_secret("mlflow_tracking_password")
        os.environ["PROJECT_ID"] = ConfigManager.project_id

    @staticmethod
    def get_odb_connection_string(region: str):
        if region == "de":
            return ConfigManager.get_secret(f"postgres_database_credentials_{region}", version="1").strip()
        return ConfigManager.get_secret(f"postgres_database_credentials_{region}", version="latest").strip()

    @staticmethod
    def get_mlflow_artifact_url():
        return ConfigManager.get_secret("mlflow_artifact_url")

    @staticmethod
    def get_signing_keys():
        return ConfigManager.get_secret("estimated_waiting_time_request_signature_allowed_secrets")

    @staticmethod
    def publish_to_bigquery(submission, title, how, region=None):
        print(f"Writing {title} to bigquery")
        if region and ConfigManager.get_env() == "prd":
            project_id = region_pids[region]

        else:
            project_id = ConfigManager.project_id
        try:
            submission.to_gbq(f"demand_forecast.{title}"
                              , project_id=project_id
                              , reauth=True
                              , credentials=ConfigManager.get_credentials(region)
                              , if_exists=how
                              , location="europe-west3")
        except Exception as e:
            print(f"Failed to write to BigQuery: {e}")
        return True

    @staticmethod
    def get_region_pid(region):
        return region_pids[region]

    @staticmethod
    def get_regions():
        return list(region_pids.keys())

    @staticmethod
    def get_credentials(region):
        if region:
            credentials = ConfigManager.get_secret(secret_id="account_credentials", region=region)
            return ConfigManager.get_credentials_json_file(credentials, "credentials.json")
        else:
            return ConfigManager.credentials

    @staticmethod
    def get_env():
        return os.environ.get("ENVIRONMENT", "dev")

    @staticmethod
    def get_local_embeddings_status():
        return ConfigManager.use_local_embeddings
    @staticmethod
    def save_secret_to_gcloud(name, secret_value):
        client = secretmanager.SecretManagerServiceClient()

        project_id = ConfigManager.project_id

        secret_name = f"projects/{project_id}/secrets/{name}"

        try:
            secret = client.get_secret(name=secret_name)
        except Exception as e:
            # Secret does not exist, create it
            parent = f"projects/{project_id}"
            secret = {
                "name": secret_name,
                "replication": {
                    "automatic": {}
                }
            }
            created_secret = client.create_secret(parent=parent, secret_id=name, secret=secret)

        try:
            # Add a new version of the secret

            version = client.add_secret_version(
                parent=secret_name,  # Use the 'name' attribute of the Secret object
                payload={"data": secret_value}
            )

            print(f"Secret '{name}' saved to Google Cloud with version: {version.name}")

            return True
        except Exception as e:
            print(f"Unable to save Secret to Google Cloud: {e}")
            return False

    @staticmethod
    def get_key_iv(key_name, version="latest", region=None):
        client = secretmanager.SecretManagerServiceClient()
        if ConfigManager.get_env() == "prd" and region:
            project_id = region_pids[region]
        else:
            project_id = ConfigManager.project_id

        secret_name = f"projects/{project_id}/secrets/{key_name}/versions/{version}"
        response = client.access_secret_version(request={"name": secret_name})
        return response.payload.data  # Return as bytes

    @staticmethod
    def destroy_secret_version(name, version):
        client = secretmanager.SecretManagerServiceClient()
        project_id = ConfigManager.project_id

        if version == "latest":
            secret_name = f"projects/{project_id}/secrets/{name}"
            response = client.list_secret_versions(request={"parent": secret_name})
            versions = list(response)
            version = versions[0].name.split("/")[-1]

        secret_version_name = f"projects/{project_id}/secrets/{name}/versions/{version}"

        try:
            client.destroy_secret_version(name=secret_version_name)
            print(f"Version '{version}' of secret '{name}' destroyed successfully.")
            return True
        except Exception as e:
            print(f"Failed to destroy version '{version}' of secret '{name}': {e}")
            return False
