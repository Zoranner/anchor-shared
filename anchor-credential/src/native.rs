//! Windows Credential Provider 的最小 COM 过滤器。
//!
//! DLL 注册和真实 LogonUI 验证均在部署流程中完成；本模块不执行注册或系统配置。

use std::{
    cell::{Cell, RefCell},
    ffi::c_void,
    mem::{size_of, zeroed},
    ptr::null_mut,
};

use windows::{
    core::{implement, Error, Interface, Result, BOOL, GUID, PCWSTR, PWSTR},
    Win32::{
        Foundation::{
            CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, E_INVALIDARG, E_NOTIMPL, S_FALSE,
        },
        Graphics::Gdi::HBITMAP,
        System::Com::{CoTaskMemAlloc, IClassFactory, IClassFactory_Impl},
        UI::Shell::{
            ICredentialProvider, ICredentialProviderCredential,
            ICredentialProviderCredentialEvents, ICredentialProviderCredential_Impl,
            ICredentialProviderEvents, ICredentialProviderFilter_Impl, ICredentialProvider_Impl,
            CPFIS_FOCUSED, CPFIS_NONE, CPFS_DISPLAY_IN_SELECTED_TILE, CPFT_COMMAND_LINK,
            CPFT_LARGE_TEXT, CPFT_SMALL_TEXT, CPGSR_NO_CREDENTIAL_NOT_FINISHED, CPSI_NONE,
            CPUS_LOGON, CPUS_UNLOCK_WORKSTATION, CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
            CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR, CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
            CREDENTIAL_PROVIDER_FIELD_STATE, CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
            CREDENTIAL_PROVIDER_STATUS_ICON, CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        },
    },
};

use crate::{
    AnchorPipeTransport, CredentialProviderController, CredentialsChanged, ImportTileStatus,
};

/// 策略导入 Provider 的 COM CLSID。
pub const ANCHOR_PROVIDER_GUID: GUID = GUID::from_u128(0x7d56dfa0_7c16_4f0b_bb35_ad2e4a3b7021);

/// 登录过滤器的 COM CLSID。
pub const ANCHOR_FILTER_GUID: GUID = GUID::from_u128(0xb4d4951b_d540_4421_a90c_19e1bbabafb8);

/// LogonUI 调用的 Credential Provider Filter。
#[implement(windows::Win32::UI::Shell::ICredentialProviderFilter)]
struct AnchorCredentialProviderFilter {
    controller: CredentialProviderController<AnchorPipeTransport>,
}

impl AnchorCredentialProviderFilter {
    fn new() -> Self {
        Self {
            controller: CredentialProviderController::new(AnchorPipeTransport),
        }
    }
}

impl Default for AnchorCredentialProviderFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl ICredentialProviderFilter_Impl for AnchorCredentialProviderFilter_Impl {
    fn Filter(
        &self,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        _dwflags: u32,
        rgclsidproviders: *const GUID,
        rgballow: *mut BOOL,
        cproviders: u32,
    ) -> Result<()> {
        if cpus != CPUS_LOGON && cpus != CPUS_UNLOCK_WORKSTATION {
            return Ok(());
        }
        if rgclsidproviders.is_null() || rgballow.is_null() {
            return Err(Error::from(windows::core::HRESULT(0x8007_0057_u32 as i32)));
        }

        if self.controller.allows_system_providers() {
            return Ok(());
        }

        // 服务无响应与明确拒绝都只保留 Anchor 的策略导入 CLSID。
        for index in 0..cproviders as usize {
            unsafe {
                *rgballow.add(index) =
                    BOOL::from(*rgclsidproviders.add(index) == ANCHOR_PROVIDER_GUID);
            }
        }
        Ok(())
    }

    fn UpdateRemoteCredential(
        &self,
        _pcpcsin: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        _pcpcsout: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> Result<()> {
        Err(Error::from(E_NOTIMPL))
    }
}

/// 是否是本 DLL 可激活的策略导入 Provider CLSID。
#[must_use]
pub fn supports_class(clsid: &GUID) -> bool {
    *clsid == ANCHOR_PROVIDER_GUID || *clsid == ANCHOR_FILTER_GUID
}

/// Anchor Provider 的 COM 类工厂。
#[implement(IClassFactory)]
struct AnchorClassFactory {
    class: AnchorComClass,
}

#[derive(Clone, Copy)]
enum AnchorComClass {
    Filter,
    Provider,
}

impl IClassFactory_Impl for AnchorClassFactory_Impl {
    fn CreateInstance(
        &self,
        punkouter: windows::core::Ref<'_, windows::core::IUnknown>,
        riid: *const GUID,
        ppvobject: *mut *mut c_void,
    ) -> Result<()> {
        if riid.is_null() || ppvobject.is_null() {
            return Err(Error::from(E_INVALIDARG));
        }
        unsafe {
            *ppvobject = null_mut();
        }
        if !punkouter.is_null() {
            return Err(Error::from(CLASS_E_NOAGGREGATION));
        }

        match self.class {
            AnchorComClass::Filter => {
                let filter: windows::Win32::UI::Shell::ICredentialProviderFilter =
                    AnchorCredentialProviderFilter::new().into();
                unsafe { filter.query(riid, ppvobject).ok() }
            }
            AnchorComClass::Provider => {
                let provider: ICredentialProvider = AnchorImportProvider::new().into();
                unsafe { provider.query(riid, ppvobject).ok() }
            }
        }
    }

    fn LockServer(&self, _flock: BOOL) -> Result<()> {
        Ok(())
    }
}

/// 返回 Anchor Provider 的类工厂；其他 CLSID 均拒绝。
pub fn class_factory_for(clsid: &GUID) -> Result<IClassFactory> {
    if !supports_class(clsid) {
        return Err(Error::from(CLASS_E_CLASSNOTAVAILABLE));
    }
    let class = if *clsid == ANCHOR_FILTER_GUID {
        AnchorComClass::Filter
    } else {
        AnchorComClass::Provider
    };
    Ok(AnchorClassFactory { class }.into())
}

/// COM DLL 激活入口。注册表只需把 Anchor CLSID 指向本 DLL。
///
/// # Safety
///
/// COM 调用方必须提供有效的 CLSID、IID 和可写的接口输出指针。输出指针由本函数
/// 初始化；其生命周期和引用计数遵循 COM 约定。
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> windows::core::HRESULT {
    if rclsid.is_null() || riid.is_null() || ppv.is_null() {
        return E_INVALIDARG;
    }
    unsafe {
        *ppv = null_mut();
    }

    let factory = match unsafe { rclsid.as_ref() }.and_then(|clsid| class_factory_for(clsid).ok()) {
        Some(factory) => factory,
        None => return CLASS_E_CLASSNOTAVAILABLE,
    };
    unsafe { factory.query(riid, ppv) }
}

/// 不报告可卸载，避免 LogonUI 持有对象时释放 DLL。
#[unsafe(no_mangle)]
pub extern "system" fn DllCanUnloadNow() -> windows::core::HRESULT {
    S_FALSE
}

/// 只含状态和导入命令的最小 Credential Provider。
#[implement(ICredentialProvider)]
struct AnchorImportProvider {
    events: RefCell<Option<ICredentialProviderEvents>>,
    advise_context: Cell<usize>,
}

impl AnchorImportProvider {
    fn new() -> Self {
        Self {
            events: RefCell::new(None),
            advise_context: Cell::new(0),
        }
    }
}

impl ICredentialProvider_Impl for AnchorImportProvider_Impl {
    fn SetUsageScenario(
        &self,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        _dwflags: u32,
    ) -> Result<()> {
        if cpus == CPUS_LOGON || cpus == CPUS_UNLOCK_WORKSTATION {
            Ok(())
        } else {
            Err(Error::from(E_NOTIMPL))
        }
    }

    fn SetSerialization(
        &self,
        _pcpcs: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> Result<()> {
        Err(Error::from(E_NOTIMPL))
    }

    fn Advise(
        &self,
        pcpe: windows::core::Ref<'_, ICredentialProviderEvents>,
        upadvisecontext: usize,
    ) -> Result<()> {
        *self.events.borrow_mut() = pcpe.cloned();
        self.advise_context.set(upadvisecontext);
        Ok(())
    }

    fn UnAdvise(&self) -> Result<()> {
        *self.events.borrow_mut() = None;
        self.advise_context.set(0);
        Ok(())
    }

    fn GetFieldDescriptorCount(&self) -> Result<u32> {
        Ok(3)
    }

    fn GetFieldDescriptorAt(
        &self,
        dwindex: u32,
    ) -> Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
        let (cpft, label) = match dwindex {
            0 => (CPFT_LARGE_TEXT, "Anchor Guard"),
            1 => (CPFT_SMALL_TEXT, "等待导入策略"),
            2 => (CPFT_COMMAND_LINK, "导入策略"),
            _ => return Err(Error::from(E_INVALIDARG)),
        };
        allocate_descriptor(dwindex, cpft, label)
    }

    fn GetCredentialCount(
        &self,
        pdwcount: *mut u32,
        pdwdefault: *mut u32,
        pbautologonwithdefault: *mut BOOL,
    ) -> Result<()> {
        if pdwcount.is_null() || pdwdefault.is_null() || pbautologonwithdefault.is_null() {
            return Err(Error::from(E_INVALIDARG));
        }
        unsafe {
            *pdwcount = 1;
            *pdwdefault = 0;
            *pbautologonwithdefault = BOOL::from(false);
        }
        Ok(())
    }

    fn GetCredentialAt(&self, dwindex: u32) -> Result<ICredentialProviderCredential> {
        if dwindex != 0 {
            return Err(Error::from(E_INVALIDARG));
        }
        Ok(
            AnchorImportCredential::new(self.events.borrow().clone(), self.advise_context.get())
                .into(),
        )
    }
}

#[implement(ICredentialProviderCredential)]
struct AnchorImportCredential {
    controller: CredentialProviderController<AnchorPipeTransport>,
    status: RefCell<ImportTileStatus>,
    provider_events: Option<ICredentialProviderEvents>,
    advise_context: usize,
}

impl AnchorImportCredential {
    fn new(provider_events: Option<ICredentialProviderEvents>, advise_context: usize) -> Self {
        Self {
            controller: CredentialProviderController::new(AnchorPipeTransport),
            status: RefCell::new(ImportTileStatus::Ready),
            provider_events,
            advise_context,
        }
    }
}

impl ICredentialProviderCredential_Impl for AnchorImportCredential_Impl {
    fn Advise(
        &self,
        _pcpce: windows::core::Ref<'_, ICredentialProviderCredentialEvents>,
    ) -> Result<()> {
        Ok(())
    }

    fn UnAdvise(&self) -> Result<()> {
        Ok(())
    }

    fn SetSelected(&self) -> Result<BOOL> {
        Ok(BOOL::from(false))
    }

    fn SetDeselected(&self) -> Result<()> {
        Ok(())
    }

    fn GetFieldState(
        &self,
        dwfieldid: u32,
        pcpfs: *mut CREDENTIAL_PROVIDER_FIELD_STATE,
        pcpfis: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    ) -> Result<()> {
        if pcpfs.is_null() || pcpfis.is_null() || dwfieldid > 2 {
            return Err(Error::from(E_INVALIDARG));
        }
        unsafe {
            *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
            *pcpfis = if dwfieldid == 2 {
                CPFIS_FOCUSED
            } else {
                CPFIS_NONE
            };
        }
        Ok(())
    }

    fn GetStringValue(&self, dwfieldid: u32) -> Result<PWSTR> {
        let status = self.status.borrow();
        let value = match dwfieldid {
            0 => "Anchor Guard",
            1 => status.message(),
            2 => "导入策略",
            _ => return Err(Error::from(E_INVALIDARG)),
        };
        allocate_wide_string(value)
    }

    fn GetBitmapValue(&self, _dwfieldid: u32) -> Result<HBITMAP> {
        Err(Error::from(E_NOTIMPL))
    }

    fn GetCheckboxValue(
        &self,
        _dwfieldid: u32,
        _pbchecked: *mut BOOL,
        _ppszlabel: *mut PWSTR,
    ) -> Result<()> {
        Err(Error::from(E_NOTIMPL))
    }

    fn GetSubmitButtonValue(&self, _dwfieldid: u32) -> Result<u32> {
        Err(Error::from(E_NOTIMPL))
    }

    fn GetComboBoxValueCount(
        &self,
        _dwfieldid: u32,
        _pcitems: *mut u32,
        _pdwselecteditem: *mut u32,
    ) -> Result<()> {
        Err(Error::from(E_NOTIMPL))
    }

    fn GetComboBoxValueAt(&self, _dwfieldid: u32, _dwitem: u32) -> Result<PWSTR> {
        Err(Error::from(E_NOTIMPL))
    }

    fn SetStringValue(&self, _dwfieldid: u32, _psz: &PCWSTR) -> Result<()> {
        Err(Error::from(E_NOTIMPL))
    }

    fn SetCheckboxValue(&self, _dwfieldid: u32, _bchecked: BOOL) -> Result<()> {
        Err(Error::from(E_NOTIMPL))
    }

    fn SetComboBoxSelectedValue(&self, _dwfieldid: u32, _dwselecteditem: u32) -> Result<()> {
        Err(Error::from(E_NOTIMPL))
    }

    fn CommandLinkClicked(&self, dwfieldid: u32) -> Result<()> {
        if dwfieldid != 2 {
            return Err(Error::from(E_INVALIDARG));
        }
        let mut notifier = ProviderEventsChanged {
            events: self.provider_events.as_ref(),
            advise_context: self.advise_context,
        };
        *self.status.borrow_mut() = self.controller.import_from_policy_media(&mut notifier);
        Ok(())
    }

    fn GetSerialization(
        &self,
        pcpgsr: *mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        pcpcs: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        ppszoptionalstatustext: *mut PWSTR,
        pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> Result<()> {
        if pcpgsr.is_null()
            || pcpcs.is_null()
            || ppszoptionalstatustext.is_null()
            || pcpsioptionalstatusicon.is_null()
        {
            return Err(Error::from(E_INVALIDARG));
        }
        unsafe {
            *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
            *pcpcs = zeroed();
            *ppszoptionalstatustext = PWSTR::null();
            *pcpsioptionalstatusicon = CPSI_NONE;
        }
        Ok(())
    }

    fn ReportResult(
        &self,
        _ntsstatus: windows::Win32::Foundation::NTSTATUS,
        _ntssubstatus: windows::Win32::Foundation::NTSTATUS,
        _ppszoptionalstatustext: *mut PWSTR,
        _pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> Result<()> {
        Ok(())
    }
}

struct ProviderEventsChanged<'a> {
    events: Option<&'a ICredentialProviderEvents>,
    advise_context: usize,
}

impl CredentialsChanged for ProviderEventsChanged<'_> {
    fn credentials_changed(&mut self) {
        if let Some(events) = self.events {
            let _ = unsafe { events.CredentialsChanged(self.advise_context) };
        }
    }
}

fn allocate_descriptor(
    field_id: u32,
    field_type: windows::Win32::UI::Shell::CREDENTIAL_PROVIDER_FIELD_TYPE,
    label: &str,
) -> Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
    let descriptor = unsafe { CoTaskMemAlloc(size_of::<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>()) }
        .cast::<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>();
    if descriptor.is_null() {
        return Err(Error::from(E_INVALIDARG));
    }
    unsafe {
        *descriptor = CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR {
            dwFieldID: field_id,
            cpft: field_type,
            pszLabel: allocate_wide_string(label)?,
            guidFieldType: GUID::zeroed(),
        };
    }
    Ok(descriptor)
}

fn allocate_wide_string(value: &str) -> Result<PWSTR> {
    let utf16: Vec<u16> = value.encode_utf16().chain(Some(0)).collect();
    let bytes = utf16.len() * size_of::<u16>();
    let allocation = unsafe { CoTaskMemAlloc(bytes) }.cast::<u16>();
    if allocation.is_null() {
        return Err(Error::from(E_INVALIDARG));
    }
    unsafe {
        allocation.copy_from_nonoverlapping(utf16.as_ptr(), utf16.len());
    }
    Ok(PWSTR(allocation))
}

#[cfg(test)]
mod tests {
    use super::{class_factory_for, supports_class, ANCHOR_FILTER_GUID, ANCHOR_PROVIDER_GUID};
    use windows::core::GUID;

    #[test]
    fn only_anchor_provider_clsid_is_activatable() {
        assert!(supports_class(&ANCHOR_PROVIDER_GUID));
        assert!(supports_class(&ANCHOR_FILTER_GUID));
        assert!(!supports_class(&GUID::zeroed()));
    }

    #[test]
    fn class_factory_accepts_anchor_clsids_and_rejects_unknown_clsid() {
        assert!(class_factory_for(&ANCHOR_PROVIDER_GUID).is_ok());
        assert!(class_factory_for(&ANCHOR_FILTER_GUID).is_ok());
        assert!(class_factory_for(&GUID::zeroed()).is_err());
    }
}
