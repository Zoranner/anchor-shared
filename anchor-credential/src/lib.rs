pub mod controller;
pub mod filter;

#[cfg(windows)]
pub mod native;

pub use controller::{
    AnchorPipeTransport, CredentialProviderController, CredentialServiceTransport,
    CredentialsChanged, ImportTile, ImportTileStatus, SERVICE_IPC_TIMEOUT,
};

#[cfg(test)]
mod controller_tests {
    use std::{
        sync::{Arc, Mutex},
        time::Duration,
    };

    use anchor_service::protocol::{
        AuthorizationResponse, ImportResponse, ServiceRequest, ServiceResponse,
    };

    use super::{
        CredentialProviderController, CredentialServiceTransport, CredentialsChanged, ImportTile,
    };

    #[derive(Clone)]
    struct RecordingTransport {
        requests: Arc<Mutex<Vec<ServiceRequest>>>,
        timeouts: Arc<Mutex<Vec<Duration>>>,
        response: Arc<Mutex<Result<ServiceResponse, &'static str>>>,
    }

    impl RecordingTransport {
        fn responding(response: Result<ServiceResponse, &'static str>) -> Self {
            Self {
                requests: Arc::default(),
                timeouts: Arc::default(),
                response: Arc::new(Mutex::new(response)),
            }
        }
    }

    impl CredentialServiceTransport for RecordingTransport {
        type Error = &'static str;

        fn transact(
            &self,
            request: ServiceRequest,
            timeout: Duration,
        ) -> Result<ServiceResponse, Self::Error> {
            self.requests.lock().unwrap().push(request);
            self.timeouts.lock().unwrap().push(timeout);
            self.response.lock().unwrap().clone()
        }
    }

    #[derive(Default)]
    struct RecordingCredentialsChanged {
        count: usize,
    }

    impl CredentialsChanged for RecordingCredentialsChanged {
        fn credentials_changed(&mut self) {
            self.count += 1;
        }
    }

    #[test]
    fn unavailable_service_denies_logon_and_only_keeps_anchor_provider() {
        let transport = RecordingTransport::responding(Err("pipe unavailable"));
        let controller = CredentialProviderController::new(transport);

        let visible = controller.filter_provider_ids(&["password".into(), "pin".into()]);

        assert_eq!(
            visible,
            vec![crate::filter::ANCHOR_PROVIDER_CLSID.to_string()]
        );
    }

    #[test]
    fn import_action_sends_only_an_import_request_and_refreshes_on_success() {
        let transport =
            RecordingTransport::responding(Ok(ServiceResponse::Import(ImportResponse {
                accepted: true,
                reason: "imported".into(),
            })));
        let controller = CredentialProviderController::new(transport.clone());
        let mut credentials_changed = RecordingCredentialsChanged::default();

        let status = controller.import_from_policy_media(&mut credentials_changed);

        assert_eq!(status.message(), "imported");
        assert_eq!(credentials_changed.count, 1);
        assert_eq!(
            *transport.requests.lock().unwrap(),
            vec![ServiceRequest::ImportFromPolicyMedia]
        );
        assert_eq!(
            *transport.timeouts.lock().unwrap(),
            vec![Duration::from_millis(500)]
        );
    }

    #[test]
    fn import_tile_keeps_the_latest_import_status_for_display() {
        let transport =
            RecordingTransport::responding(Ok(ServiceResponse::Import(ImportResponse {
                accepted: false,
                reason: "invalid_signature".into(),
            })));
        let mut tile = ImportTile::new(CredentialProviderController::new(transport));
        let mut credentials_changed = RecordingCredentialsChanged::default();

        tile.import_from_policy_media(&mut credentials_changed);

        assert_eq!(tile.status().message(), "invalid_signature");
        assert_eq!(credentials_changed.count, 0);
    }

    #[test]
    fn allowed_authorization_keeps_all_system_providers() {
        let transport = RecordingTransport::responding(Ok(ServiceResponse::Authorization(
            AuthorizationResponse::Allowed,
        )));
        let controller = CredentialProviderController::new(transport);

        let visible = controller.filter_provider_ids(&["password".into(), "pin".into()]);

        assert_eq!(visible, vec!["password", "pin"]);
    }
}
