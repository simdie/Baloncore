use crate::lifecycle::{FindingRecord, FindingState};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Web3ProjectKind {
    Foundry,
    Hardhat,
    Truffle,
    Brownie,
    Unknown,
}

impl Web3ProjectKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Foundry => "foundry",
            Self::Hardhat => "hardhat",
            Self::Truffle => "truffle",
            Self::Brownie => "brownie",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "foundry" => Self::Foundry,
            "hardhat" => Self::Hardhat,
            "truffle" => Self::Truffle,
            "brownie" => Self::Brownie,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum SolidityType {
    Uint8,
    Uint16,
    Uint32,
    Uint64,
    Uint128,
    Uint256,
    Int8,
    Int16,
    Int32,
    Int64,
    Int128,
    Int256,
    Address,
    Bool,
    String,
    Bytes,
    Bytes32,
    Mapping(Box<SolidityType>, Box<SolidityType>),
    Array(Box<SolidityType>),
    Custom(String),
    Void,
}

impl SolidityType {
    pub fn is_integer(&self) -> bool {
        matches!(
            self,
            Self::Uint8
                | Self::Uint16
                | Self::Uint32
                | Self::Uint64
                | Self::Uint128
                | Self::Uint256
                | Self::Int8
                | Self::Int16
                | Self::Int32
                | Self::Int64
                | Self::Int128
                | Self::Int256
        )
    }

    pub fn is_unsigned(&self) -> bool {
        matches!(
            self,
            Self::Uint8
                | Self::Uint16
                | Self::Uint32
                | Self::Uint64
                | Self::Uint128
                | Self::Uint256
        )
    }

    pub fn is_mapping(&self) -> bool {
        matches!(self, Self::Mapping(_, _))
    }

    pub fn from_str_lossy(s: &str) -> Self {
        let s = s.trim();
        if s == "uint8" {
            Self::Uint8
        } else if s == "uint16" {
            Self::Uint16
        } else if s == "uint32" {
            Self::Uint32
        } else if s == "uint64" {
            Self::Uint64
        } else if s == "uint128" {
            Self::Uint128
        } else if s == "uint256" || s.starts_with("uint") {
            Self::Uint256
        } else if s == "int8" {
            Self::Int8
        } else if s == "int16" {
            Self::Int16
        } else if s == "int32" {
            Self::Int32
        } else if s == "int64" {
            Self::Int64
        } else if s == "int128" {
            Self::Int128
        } else if s == "int256" || s == "int" || s.starts_with("int") {
            Self::Int256
        } else if s == "address" {
            Self::Address
        } else if s == "bool" {
            Self::Bool
        } else if s == "string" {
            Self::String
        } else if s == "bytes" {
            Self::Bytes
        } else if s == "bytes32" {
            Self::Bytes32
        } else if s.starts_with("mapping(") {
            Self::Mapping(Box::new(Self::Address), Box::new(Self::Uint256))
        } else if s.ends_with("[]") {
            Self::Array(Box::new(Self::Uint256))
        } else if !s.is_empty() {
            Self::Custom(s.to_string())
        } else {
            Self::Void
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum FunctionVisibility {
    Public,
    External,
    Internal,
    Private,
}

impl FunctionVisibility {
    pub fn is_accessible(&self) -> bool {
        matches!(self, Self::Public | Self::External)
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "public" => Self::Public,
            "external" => Self::External,
            "internal" => Self::Internal,
            "private" => Self::Private,
            _ => Self::Public,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum StateMutability {
    Pure,
    View,
    NonPayable,
    Payable,
}

impl StateMutability {
    pub fn is_read_only(&self) -> bool {
        matches!(self, Self::Pure | Self::View)
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "pure" => Self::Pure,
            "view" => Self::View,
            "payable" => Self::Payable,
            _ => Self::NonPayable,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum InvariantKind {
    ShareAccounting,
    ConservationOfAssets,
    AuthorizationCheck,
    OracleFreshness,
    ReplayResistance,
    LiquidationHealth,
    BridgeMessageUniqueness,
    AccessControl,
    UpgradeSafety,
    RoundingSafety,
    DecimalConsistency,
    DepositWithdrawalBalance,
    TotalSupplyInvariant,
    Custom(String),
}

impl InvariantKind {
    pub fn as_str(&self) -> &str {
        match self {
            Self::ShareAccounting => "share_accounting",
            Self::ConservationOfAssets => "conservation_of_assets",
            Self::AuthorizationCheck => "authorization_check",
            Self::OracleFreshness => "oracle_freshness",
            Self::ReplayResistance => "replay_resistance",
            Self::LiquidationHealth => "liquidation_health",
            Self::BridgeMessageUniqueness => "bridge_message_uniqueness",
            Self::AccessControl => "access_control",
            Self::UpgradeSafety => "upgrade_safety",
            Self::RoundingSafety => "rounding_safety",
            Self::DecimalConsistency => "decimal_consistency",
            Self::DepositWithdrawalBalance => "deposit_withdrawal_balance",
            Self::TotalSupplyInvariant => "total_supply_invariant",
            Self::Custom(s) => s,
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "share_accounting" => Self::ShareAccounting,
            "conservation_of_assets" => Self::ConservationOfAssets,
            "authorization_check" => Self::AuthorizationCheck,
            "oracle_freshness" => Self::OracleFreshness,
            "replay_resistance" => Self::ReplayResistance,
            "liquidation_health" => Self::LiquidationHealth,
            "bridge_message_uniqueness" => Self::BridgeMessageUniqueness,
            "access_control" => Self::AccessControl,
            "upgrade_safety" => Self::UpgradeSafety,
            "rounding_safety" => Self::RoundingSafety,
            "decimal_consistency" => Self::DecimalConsistency,
            "deposit_withdrawal_balance" => Self::DepositWithdrawalBalance,
            "total_supply_invariant" => Self::TotalSupplyInvariant,
            _ => Self::Custom(s.to_string()),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum VulnerabilityClass {
    Reentrancy,
    AccessControl,
    ArithmeticOverflow,
    ArithmeticUnderflow,
    RoundingError,
    FrontRunning,
    OracleManipulation,
    FlashLoanAttack,
    SignatureReplay,
    UncheckedReturn,
    DenialOfService,
    CentralizationRisk,
    UpgradeabilityRisk,
    IncorrectEquality,
    UninitializedStorage,
    DelegatecallRisk,
    TxOriginAuth,
    TimestampDependence,
    SelfDestruction,
    InsufficientValidation,
    Custom(String),
}

impl VulnerabilityClass {
    pub fn as_str(&self) -> &str {
        match self {
            Self::Reentrancy => "reentrancy",
            Self::AccessControl => "access_control",
            Self::ArithmeticOverflow => "arithmetic_overflow",
            Self::ArithmeticUnderflow => "arithmetic_underflow",
            Self::RoundingError => "rounding_error",
            Self::FrontRunning => "front_running",
            Self::OracleManipulation => "oracle_manipulation",
            Self::FlashLoanAttack => "flash_loan_attack",
            Self::SignatureReplay => "signature_replay",
            Self::UncheckedReturn => "unchecked_return",
            Self::DenialOfService => "denial_of_service",
            Self::CentralizationRisk => "centralization_risk",
            Self::UpgradeabilityRisk => "upgradeability_risk",
            Self::IncorrectEquality => "incorrect_equality",
            Self::UninitializedStorage => "uninitialized_storage",
            Self::DelegatecallRisk => "delegatecall_risk",
            Self::TxOriginAuth => "tx_origin_auth",
            Self::TimestampDependence => "timestamp_dependence",
            Self::SelfDestruction => "self_destruction",
            Self::InsufficientValidation => "insufficient_validation",
            Self::Custom(s) => s,
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s {
            "reentrancy" => Self::Reentrancy,
            "access_control" => Self::AccessControl,
            "arithmetic_overflow" => Self::ArithmeticOverflow,
            "arithmetic_underflow" => Self::ArithmeticUnderflow,
            "rounding_error" => Self::RoundingError,
            "front_running" => Self::FrontRunning,
            "oracle_manipulation" => Self::OracleManipulation,
            "flash_loan_attack" => Self::FlashLoanAttack,
            "signature_replay" => Self::SignatureReplay,
            "unchecked_return" => Self::UncheckedReturn,
            "denial_of_service" => Self::DenialOfService,
            "centralization_risk" => Self::CentralizationRisk,
            "upgradeability_risk" => Self::UpgradeabilityRisk,
            "incorrect_equality" => Self::IncorrectEquality,
            "uninitialized_storage" => Self::UninitializedStorage,
            "delegatecall_risk" => Self::DelegatecallRisk,
            "tx_origin_auth" => Self::TxOriginAuth,
            "timestamp_dependence" => Self::TimestampDependence,
            "self_destruction" => Self::SelfDestruction,
            "insufficient_validation" => Self::InsufficientValidation,
            _ => Self::Custom(s.to_string()),
        }
    }

    pub fn to_severity(&self) -> Web3Severity {
        match self {
            Self::Reentrancy => Web3Severity::Critical,
            Self::AccessControl => Web3Severity::High,
            Self::ArithmeticOverflow | Self::ArithmeticUnderflow => Web3Severity::High,
            Self::RoundingError => Web3Severity::Medium,
            Self::FrontRunning => Web3Severity::Medium,
            Self::OracleManipulation => Web3Severity::Critical,
            Self::FlashLoanAttack => Web3Severity::Critical,
            Self::SignatureReplay => Web3Severity::High,
            Self::UncheckedReturn => Web3Severity::Medium,
            Self::DenialOfService => Web3Severity::Medium,
            Self::CentralizationRisk => Web3Severity::High,
            Self::UpgradeabilityRisk => Web3Severity::Medium,
            Self::IncorrectEquality => Web3Severity::Medium,
            Self::UninitializedStorage => Web3Severity::High,
            Self::DelegatecallRisk => Web3Severity::Critical,
            Self::TxOriginAuth => Web3Severity::Medium,
            Self::TimestampDependence => Web3Severity::Low,
            Self::SelfDestruction => Web3Severity::High,
            Self::InsufficientValidation => Web3Severity::Medium,
            Self::Custom(_) => Web3Severity::Medium,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Web3Severity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

impl Web3Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Informational => "informational",
        }
    }

    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "critical" | "crit" => Self::Critical,
            "high" => Self::High,
            "medium" | "med" => Self::Medium,
            "low" => Self::Low,
            _ => Self::Informational,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SolidityFunction {
    pub name: String,
    pub visibility: FunctionVisibility,
    pub state_mutability: StateMutability,
    pub parameters: Vec<SolidityParameter>,
    pub return_types: Vec<SolidityType>,
    pub modifiers: Vec<String>,
    pub is_payable: bool,
    pub source_location: Option<SourceLocation>,
}

impl SolidityFunction {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            visibility: FunctionVisibility::Public,
            state_mutability: StateMutability::NonPayable,
            parameters: Vec::new(),
            return_types: Vec::new(),
            modifiers: Vec::new(),
            is_payable: false,
            source_location: None,
        }
    }

    pub fn with_visibility(mut self, v: FunctionVisibility) -> Self {
        self.visibility = v;
        self
    }

    pub fn with_state_mutability(mut self, sm: StateMutability) -> Self {
        self.state_mutability = sm;
        self
    }

    pub fn with_parameter(mut self, name: impl Into<String>, ty: SolidityType) -> Self {
        self.parameters.push(SolidityParameter {
            name: name.into(),
            ty,
            indexed: false,
        });
        self
    }

    pub fn with_return_type(mut self, ty: SolidityType) -> Self {
        self.return_types.push(ty);
        self
    }

    pub fn with_modifier(mut self, m: impl Into<String>) -> Self {
        self.modifiers.push(m.into());
        self
    }

    pub fn with_payable(mut self) -> Self {
        self.is_payable = true;
        self.state_mutability = StateMutability::Payable;
        self
    }

    pub fn with_source_location(mut self, file: impl Into<String>, line: usize) -> Self {
        self.source_location = Some(SourceLocation {
            file: file.into(),
            line,
        });
        self
    }

    pub fn signature(&self) -> String {
        let params: Vec<String> = self.parameters.iter().map(|p| format_ty(&p.ty)).collect();
        format!("{}({})", self.name, params.join(","))
    }

    pub fn is_accessor(&self) -> bool {
        self.state_mutability.is_read_only()
            && self.visibility.is_accessible()
            && self.parameters.is_empty()
    }

    pub fn is_state_changing(&self) -> bool {
        !self.state_mutability.is_read_only()
    }
}

fn format_ty(ty: &SolidityType) -> String {
    match ty {
        SolidityType::Uint8 => "uint8".to_string(),
        SolidityType::Uint16 => "uint16".to_string(),
        SolidityType::Uint32 => "uint32".to_string(),
        SolidityType::Uint64 => "uint64".to_string(),
        SolidityType::Uint128 => "uint128".to_string(),
        SolidityType::Uint256 => "uint256".to_string(),
        SolidityType::Int8 => "int8".to_string(),
        SolidityType::Int16 => "int16".to_string(),
        SolidityType::Int32 => "int32".to_string(),
        SolidityType::Int64 => "int64".to_string(),
        SolidityType::Int128 => "int128".to_string(),
        SolidityType::Int256 => "int256".to_string(),
        SolidityType::Address => "address".to_string(),
        SolidityType::Bool => "bool".to_string(),
        SolidityType::String => "string".to_string(),
        SolidityType::Bytes => "bytes".to_string(),
        SolidityType::Bytes32 => "bytes32".to_string(),
        SolidityType::Mapping(k, v) => format!("mapping({} => {})", format_ty(k), format_ty(v)),
        SolidityType::Array(inner) => format!("{}[]", format_ty(inner)),
        SolidityType::Custom(s) => s.clone(),
        SolidityType::Void => "void".to_string(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SolidityParameter {
    pub name: String,
    pub ty: SolidityType,
    pub indexed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SourceLocation {
    pub file: String,
    pub line: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SolidityEvent {
    pub name: String,
    pub parameters: Vec<SolidityParameter>,
    pub source_location: Option<SourceLocation>,
}

impl SolidityEvent {
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            parameters: Vec::new(),
            source_location: None,
        }
    }

    pub fn with_parameter(
        mut self,
        name: impl Into<String>,
        ty: SolidityType,
        indexed: bool,
    ) -> Self {
        self.parameters.push(SolidityParameter {
            name: name.into(),
            ty,
            indexed,
        });
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ContractKind {
    Contract,
    Interface,
    Library,
    Abstract,
}

impl ContractKind {
    pub fn from_str_lossy(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "interface" => Self::Interface,
            "library" => Self::Library,
            "abstract" => Self::Abstract,
            _ => Self::Contract,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StorageLayout {
    Storage,
    Memory,
    Calldata,
    Stack,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StorageVariable {
    pub name: String,
    pub ty: SolidityType,
    pub visibility: FunctionVisibility,
    pub is_constant: bool,
    pub is_immutable: bool,
    pub initial_value: Option<String>,
}

impl StorageVariable {
    pub fn new(name: impl Into<String>, ty: SolidityType) -> Self {
        Self {
            name: name.into(),
            ty,
            visibility: FunctionVisibility::Private,
            is_constant: false,
            is_immutable: false,
            initial_value: None,
        }
    }

    pub fn with_visibility(mut self, v: FunctionVisibility) -> Self {
        self.visibility = v;
        self
    }

    pub fn is_publicly_readable(&self) -> bool {
        self.visibility.is_accessible() || self.is_constant
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InheritanceRelation {
    pub contract: String,
    pub parent: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolidityContract {
    pub name: String,
    pub kind: ContractKind,
    pub file: String,
    pub functions: Vec<SolidityFunction>,
    pub events: Vec<SolidityEvent>,
    pub state_variables: Vec<StorageVariable>,
    pub inherits: Vec<String>,
    pub modifiers: Vec<String>,
    pub linearized_base_contracts: Vec<String>,
    pub is_upgradeable: bool,
    pub uses_oracle: bool,
    pub uses_delegation: bool,
    pub is_erc20: bool,
    pub is_erc721: bool,
    pub is_erc1155: bool,
    pub source_location: Option<SourceLocation>,
}

impl SolidityContract {
    pub fn new(name: impl Into<String>, file: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: ContractKind::Contract,
            file: file.into(),
            functions: Vec::new(),
            events: Vec::new(),
            state_variables: Vec::new(),
            inherits: Vec::new(),
            modifiers: Vec::new(),
            linearized_base_contracts: Vec::new(),
            is_upgradeable: false,
            uses_oracle: false,
            uses_delegation: false,
            is_erc20: false,
            is_erc721: false,
            is_erc1155: false,
            source_location: None,
        }
    }

    pub fn with_kind(mut self, kind: ContractKind) -> Self {
        self.kind = kind;
        self
    }

    pub fn with_function(mut self, f: SolidityFunction) -> Self {
        self.functions.push(f);
        self
    }

    pub fn with_event(mut self, e: SolidityEvent) -> Self {
        self.events.push(e);
        self
    }

    pub fn with_state_variable(mut self, v: StorageVariable) -> Self {
        self.state_variables.push(v);
        self
    }

    pub fn with_inherits(mut self, parent: impl Into<String>) -> Self {
        self.inherits.push(parent.into());
        self
    }

    pub fn with_modifier(mut self, m: impl Into<String>) -> Self {
        self.modifiers.push(m.into());
        self
    }

    pub fn upgradeable(mut self) -> Self {
        self.is_upgradeable = true;
        self
    }

    pub fn uses_oracle(mut self) -> Self {
        self.uses_oracle = true;
        self
    }

    pub fn uses_delegation(mut self) -> Self {
        self.uses_delegation = true;
        self
    }

    pub fn erc20(mut self) -> Self {
        self.is_erc20 = true;
        self
    }

    pub fn erc721(mut self) -> Self {
        self.is_erc721 = true;
        self
    }

    pub fn erc1155(mut self) -> Self {
        self.is_erc1155 = true;
        self
    }

    pub fn public_functions(&self) -> Vec<&SolidityFunction> {
        self.functions
            .iter()
            .filter(|f| f.visibility.is_accessible())
            .collect()
    }

    pub fn state_changing_functions(&self) -> Vec<&SolidityFunction> {
        self.functions
            .iter()
            .filter(|f| f.is_state_changing())
            .collect()
    }

    pub fn payable_functions(&self) -> Vec<&SolidityFunction> {
        self.functions.iter().filter(|f| f.is_payable).collect()
    }

    pub fn external_functions(&self) -> Vec<&SolidityFunction> {
        self.functions
            .iter()
            .filter(|f| f.visibility == FunctionVisibility::External)
            .collect()
    }

    pub fn function_signatures(&self) -> Vec<String> {
        self.functions.iter().map(|f| f.signature()).collect()
    }

    fn detect_erc20(&mut self) {
        let required_sigs: HashSet<String> = [
            "totalSupply()",
            "balanceOf(address)",
            "transfer(address,uint256)",
            "approve(address,uint256)",
            "allowance(address,address)",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let found: HashSet<String> = self.function_signatures().into_iter().collect();
        if required_sigs.is_subset(&found) {
            self.is_erc20 = true;
        }
    }

    fn detect_erc721(&mut self) {
        let required_sigs: HashSet<String> = [
            "balanceOf(address)",
            "ownerOf(uint256)",
            "transferFrom(address,address,uint256)",
            "approve(address,uint256)",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();

        let found: HashSet<String> = self.function_signatures().into_iter().collect();
        if required_sigs.is_subset(&found) {
            self.is_erc721 = true;
        }
    }

    fn detect_upgradeable(&mut self) {
        if self.inherits.iter().any(|p| {
            p.contains("Initializable")
                || p.contains("UUPSUpgradeable")
                || p.contains("TransparentUpgradeableProxy")
        }) || self.state_variables.iter().any(|v| {
            v.name == "_initialized" || v.name == "__initialized" || v.name == "_upgradeable"
        }) {
            self.is_upgradeable = true;
        }
    }

    fn detect_oracle(&mut self) {
        if self.inherits.iter().any(|p| {
            p.contains("Oracle")
                || p.contains("Chainlink")
                || p.contains("AggregatorV3Interface")
                || p.contains("PriceFeed")
        }) || self.functions.iter().any(|f| {
            f.name.contains("price")
                || f.name.contains("oracle")
                || f.name.contains("latestRoundData")
        }) {
            self.uses_oracle = true;
        }
    }

    fn detect_delegation(&mut self) {
        if self
            .functions
            .iter()
            .any(|f| f.name == "delegatecall" || f.name == "_delegatecall" || f.name == "execute")
            || self
                .state_variables
                .iter()
                .any(|v| v.name.contains("implementation") || v.name.contains("_delegate"))
        {
            self.uses_delegation = true;
        }
    }

    pub fn detect_patterns(&mut self) {
        self.detect_erc20();
        self.detect_erc721();
        self.detect_upgradeable();
        self.detect_oracle();
        self.detect_delegation();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web3Project {
    pub name: String,
    pub path: String,
    pub kind: Web3ProjectKind,
    pub contracts: Vec<SolidityContract>,
    pub inheritance_relations: Vec<InheritanceRelation>,
    pub foundry_config: Option<FoundryConfig>,
    pub hardhat_config: Option<HardhatConfig>,
    pub slither_version: Option<String>,
}

impl Web3Project {
    pub fn new(name: impl Into<String>, path: impl Into<String>, kind: Web3ProjectKind) -> Self {
        Self {
            name: name.into(),
            path: path.into(),
            kind,
            contracts: Vec::new(),
            inheritance_relations: Vec::new(),
            foundry_config: None,
            hardhat_config: None,
            slither_version: None,
        }
    }

    pub fn with_contract(mut self, c: SolidityContract) -> Self {
        self.contracts.push(c);
        self
    }

    pub fn with_inheritance(
        mut self,
        contract: impl Into<String>,
        parent: impl Into<String>,
    ) -> Self {
        self.inheritance_relations.push(InheritanceRelation {
            contract: contract.into(),
            parent: parent.into(),
        });
        self
    }

    pub fn contract_by_name(&self, name: &str) -> Option<&SolidityContract> {
        self.contracts.iter().find(|c| c.name == name)
    }

    pub fn total_functions(&self) -> usize {
        self.contracts.iter().map(|c| c.functions.len()).sum()
    }

    pub fn public_functions(&self) -> Vec<(&SolidityContract, &SolidityFunction)> {
        self.contracts
            .iter()
            .flat_map(|c| c.public_functions().into_iter().map(move |f| (c, f)))
            .collect()
    }

    pub fn state_changing_functions(&self) -> Vec<(&SolidityContract, &SolidityFunction)> {
        self.contracts
            .iter()
            .flat_map(|c| {
                c.state_changing_functions()
                    .into_iter()
                    .map(move |f| (c, f))
            })
            .collect()
    }

    pub fn payable_functions(&self) -> Vec<(&SolidityContract, &SolidityFunction)> {
        self.contracts
            .iter()
            .flat_map(|c| c.payable_functions().into_iter().map(move |f| (c, f)))
            .collect()
    }

    pub fn is_erc20(&self) -> bool {
        self.contracts.iter().any(|c| c.is_erc20)
    }

    pub fn is_erc721(&self) -> bool {
        self.contracts.iter().any(|c| c.is_erc721)
    }

    pub fn is_upgradeable(&self) -> bool {
        self.contracts.iter().any(|c| c.is_upgradeable)
    }

    pub fn uses_oracle(&self) -> bool {
        self.contracts.iter().any(|c| c.uses_oracle)
    }

    pub fn uses_delegation(&self) -> bool {
        self.contracts.iter().any(|c| c.uses_delegation)
    }

    pub fn detect_all_patterns(&mut self) {
        self.contracts.iter_mut().for_each(|c| c.detect_patterns());
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FoundryConfig {
    pub profile: String,
    pub optimizer_runs: Option<u32>,
    pub evm_version: Option<String>,
    pub solidity_version: Option<String>,
    pub fuzz_runs: Option<u32>,
    pub invariant_runs: Option<u32>,
    pub timeout: Option<u32>,
    pub test_pattern: Option<String>,
}

impl FoundryConfig {
    pub fn default_profile() -> Self {
        Self {
            profile: "default".to_string(),
            optimizer_runs: None,
            evm_version: None,
            solidity_version: None,
            fuzz_runs: None,
            invariant_runs: None,
            timeout: None,
            test_pattern: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardhatConfig {
    pub solidity_version: Option<String>,
    pub optimizer_enabled: bool,
    pub optimizer_runs: Option<u32>,
    pub networks: HashMap<String, String>,
}

impl HardhatConfig {
    pub fn default_config() -> Self {
        Self {
            solidity_version: None,
            optimizer_enabled: false,
            optimizer_runs: None,
            networks: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum InvariantStatus {
    Generated,
    Fuzzing,
    Violated,
    Passed,
    Timeout,
    Error(String),
}

impl InvariantStatus {
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::Violated | Self::Passed | Self::Timeout | Self::Error(_)
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantSpec {
    pub id: String,
    pub kind: InvariantKind,
    pub name: String,
    pub description: String,
    pub contract: String,
    pub function_selector: Option<String>,
    pub expression: String,
    pub preconditions: Vec<String>,
    pub severity: Web3Severity,
    pub vulnerability_class: VulnerabilityClass,
    pub status: InvariantStatus,
    pub fuzz_runs: Option<u32>,
    pub violation_sequence: Option<Vec<String>>,
    pub source_template: String,
}

impl InvariantSpec {
    pub fn new(
        id: impl Into<String>,
        kind: InvariantKind,
        contract: impl Into<String>,
        expression: impl Into<String>,
        vuln_class: VulnerabilityClass,
    ) -> Self {
        let kind_str = kind.as_str();
        let contract = contract.into();
        let expression = expression.into();
        let id = id.into();
        let name = format!("{}_{}", kind_str, &contract);
        let description = format!("Invariant: {} for contract {}", expression, contract);
        let severity = vuln_class.to_severity();
        Self {
            id,
            name,
            description,
            contract,
            kind,
            function_selector: None,
            expression,
            preconditions: Vec::new(),
            severity,
            vulnerability_class: vuln_class,
            status: InvariantStatus::Generated,
            fuzz_runs: None,
            violation_sequence: None,
            source_template: "auto".to_string(),
        }
    }

    pub fn with_precondition(mut self, cond: impl Into<String>) -> Self {
        self.preconditions.push(cond.into());
        self
    }

    pub fn with_function_selector(mut self, selector: impl Into<String>) -> Self {
        self.function_selector = Some(selector.into());
        self
    }

    pub fn with_fuzz_runs(mut self, runs: u32) -> Self {
        self.fuzz_runs = Some(runs);
        self
    }

    pub fn with_violation_sequence(mut self, sequence: Vec<String>) -> Self {
        self.violation_sequence = Some(sequence);
        self
    }

    pub fn with_status(mut self, status: InvariantStatus) -> Self {
        self.status = status;
        self
    }

    pub fn to_foundry_test_code(&self) -> String {
        let test_name = format!("test_{}", self.name);
        let precondition_block = if self.preconditions.is_empty() {
            String::new()
        } else {
            let conds: Vec<String> = self
                .preconditions
                .iter()
                .map(|p| format!("        vm.assume({});", p))
                .collect();
            format!("\n{}", conds.join("\n"))
        };
        let contract_path = format!("../src/{}.sol", self.contract);
        let contract = &self.contract;
        let name = &self.name;
        let desc = &self.description;
        let expr = &self.expression;
        let pre = &precondition_block;
        match &self.kind {
            InvariantKind::ShareAccounting => {
                format!(
                    r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "{contract_path}";
import "forge-std/Test.sol";

contract {test_name} is Test {{
    {contract} target;

    function setUp() public {{
        target = new {contract}();
    }}

    function {name}() public {{{pre}
        // {desc}
        {expr}
    }}
}}
"#,
                    contract_path = contract_path,
                    test_name = test_name,
                    contract = contract,
                    name = name,
                    pre = pre,
                    desc = desc,
                    expr = expr,
                )
            }
            InvariantKind::ConservationOfAssets => {
                format!(
                    r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "{contract_path}";
import "forge-std/Test.sol";

contract {test_name} is Test {{
    {contract} target;

    function setUp() public {{
        target = new {contract}();
    }}

    function {name}() public {{{pre}
        // {desc}
        uint256 totalBefore = target.totalSupply();
        {expr}
        uint256 totalAfter = target.totalSupply();
        assertEq(totalBefore, totalAfter);
    }}
}}
"#,
                    contract_path = contract_path,
                    test_name = test_name,
                    contract = contract,
                    name = name,
                    pre = pre,
                    desc = desc,
                    expr = expr,
                )
            }
            _ => {
                format!(
                    r#"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "{contract_path}";
import "forge-std/Test.sol";

contract {test_name} is Test {{
    {contract} target;

    function setUp() public {{
        target = new {contract}();
    }}

    function {name}() public {{{pre}
        // {desc}
        {expr}
    }}
}}
"#,
                    contract_path = contract_path,
                    test_name = test_name,
                    contract = contract,
                    name = name,
                    pre = pre,
                    desc = desc,
                    expr = expr,
                )
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvariantTemplate {
    pub kind: InvariantKind,
    pub name: String,
    pub description: String,
    pub expression_template: String,
    pub applicable_patterns: Vec<String>,
    pub vulnerability_class: VulnerabilityClass,
    pub preconditions_template: Vec<String>,
}

pub fn invariant_template_library() -> Vec<InvariantTemplate> {
    vec![
        InvariantTemplate {
            kind: InvariantKind::ShareAccounting,
            name: "share_accounting_balance".to_string(),
            description: "Total shares must always equal total assets deposited minus total assets withdrawn".to_string(),
            expression_template: "assertEq(target.totalShares(), target.totalAssets() - target.totalDebt())".to_string(),
            applicable_patterns: vec!["ERC4626".to_string(), "vault".to_string(), "share".to_string()],
            vulnerability_class: VulnerabilityClass::RoundingError,
            preconditions_template: vec!["deposits > 0".to_string()],
        },
        InvariantTemplate {
            kind: InvariantKind::ConservationOfAssets,
            name: "conservation_of_assets".to_string(),
            description: "Total assets must equal sum of all deposits minus sum of all withdrawals".to_string(),
            expression_template: "assertEq(target.totalAssets(), expectedTotalAssets)".to_string(),
            applicable_patterns: vec!["ERC4626".to_string(), "vault".to_string(), "pool".to_string(), "deposit".to_string()],
            vulnerability_class: VulnerabilityClass::ArithmeticOverflow,
            preconditions_template: vec!["totalDeposits > 0".to_string()],
        },
        InvariantTemplate {
            kind: InvariantKind::AuthorizationCheck,
            name: "only_owner_restricted".to_string(),
            description: "Only owner can call restricted functions".to_string(),
            expression_template: "vm.prank(notOwner); vm.expectRevert(); target.restrictedFunction()".to_string(),
            applicable_patterns: vec!["Ownable".to_string(), "AccessControl".to_string(), "admin".to_string(), "owner".to_string()],
            vulnerability_class: VulnerabilityClass::AccessControl,
            preconditions_template: vec!["msg.sender != owner".to_string()],
        },
        InvariantTemplate {
            kind: InvariantKind::OracleFreshness,
            name: "oracle_price_fresh".to_string(),
            description: "Oracle price must not be stale (within max staleness window)".to_string(),
            expression_template: "assertLt(block.timestamp - target.latestTimestamp(), maxStaleness)".to_string(),
            applicable_patterns: vec!["Oracle".to_string(), "Chainlink".to_string(), "PriceFeed".to_string()],
            vulnerability_class: VulnerabilityClass::OracleManipulation,
            preconditions_template: vec!["oracleAlive".to_string()],
        },
        InvariantTemplate {
            kind: InvariantKind::ReplayResistance,
            name: "signature_replay_resistance".to_string(),
            description: "Same signature must not be usable twice".to_string(),
            expression_template: "vm.expectRevert(); target.executeWithSignature(sameNonce, sameSignature)".to_string(),
            applicable_patterns: vec!["ECDSA".to_string(), "metaTransaction".to_string(), "permit".to_string()],
            vulnerability_class: VulnerabilityClass::SignatureReplay,
            preconditions_template: vec!["signatureUsed == false".to_string()],
        },
        InvariantTemplate {
            kind: InvariantKind::LiquidationHealth,
            name: "liquidation_health_factor".to_string(),
            description: "Liquidations must maintain health factor above threshold".to_string(),
            expression_template: "assertGe(target.getHealthFactor(borrower), minHealthFactor)".to_string(),
            applicable_patterns: vec!["Lending".to_string(), "Liquidate".to_string(), "Borrow".to_string(), "Aave".to_string()],
            vulnerability_class: VulnerabilityClass::ArithmeticOverflow,
            preconditions_template: vec!["collateralValue > 0".to_string(), "borrowAmount > 0".to_string()],
        },
        InvariantTemplate {
            kind: InvariantKind::BridgeMessageUniqueness,
            name: "bridge_message_uniqueness".to_string(),
            description: "Each bridge message must be processed exactly once".to_string(),
            expression_template: "vm.expectRevert(); target.processMessage(sameMessageId)".to_string(),
            applicable_patterns: vec!["Bridge".to_string(), "CrossChain".to_string(), "Relay".to_string()],
            vulnerability_class: VulnerabilityClass::SignatureReplay,
            preconditions_template: vec!["messageNotProcessed".to_string()],
        },
        InvariantTemplate {
            kind: InvariantKind::AccessControl,
            name: "role_based_access".to_string(),
            description: "Functions with role restrictions must reject unauthorized callers".to_string(),
            expression_template: "vm.prank(unauthorized); vm.expectRevert(); target.restrictedFunction()".to_string(),
            applicable_patterns: vec!["_onlyRole".to_string(), "onlyAdmin".to_string(), "modifier".to_string()],
            vulnerability_class: VulnerabilityClass::AccessControl,
            preconditions_template: vec!["caller lacks required role".to_string()],
        },
        InvariantTemplate {
            kind: InvariantKind::UpgradeSafety,
            name: "upgrade_storage_layout".to_string(),
            description: "Upgrade must not break storage layout".to_string(),
            expression_template: "assertEq(storageSlotValue_before, storageSlotValue_after)".to_string(),
            applicable_patterns: vec!["UUPSUpgradeable".to_string(), "TransparentUpgradeableProxy".to_string(), "Initializable".to_string()],
            vulnerability_class: VulnerabilityClass::UpgradeabilityRisk,
            preconditions_template: vec!["proxyInitialized".to_string()],
        },
        InvariantTemplate {
            kind: InvariantKind::RoundingSafety,
            name: "rounding_no_loss".to_string(),
            description: "Rounding must not cause loss of precision exceeding acceptable threshold".to_string(),
            expression_template: "assertLe(abs(target.convertToShares(assets) * target.convertToAssets(shares) - assets * shares), threshold)".to_string(),
            applicable_patterns: vec!["ERC4626".to_string(), "vault".to_string(), "share".to_string(), "convert".to_string()],
            vulnerability_class: VulnerabilityClass::RoundingError,
            preconditions_template: vec!["assets > 0".to_string(), "shares > 0".to_string()],
        },
        InvariantTemplate {
            kind: InvariantKind::DecimalConsistency,
            name: "decimal_consistency".to_string(),
            description: "Token decimals must be consistent across all operations".to_string(),
            expression_template: "assertEq(target.decimals(), expectedDecimals)".to_string(),
            applicable_patterns: vec!["ERC20".to_string(), "ERC20Metadata".to_string(), "decimals".to_string()],
            vulnerability_class: VulnerabilityClass::IncorrectEquality,
            preconditions_template: vec!["tokenDeployed".to_string()],
        },
        InvariantTemplate {
            kind: InvariantKind::DepositWithdrawalBalance,
            name: "deposit_withdrawal_no_drain".to_string(),
            description: "Depositing and then withdrawing the same amount must not drain the contract".to_string(),
            expression_template: "uint256 before = target.totalAssets(); target.deposit(amount, user); target.withdraw(amount, user, user); assertEq(target.totalAssets(), before)".to_string(),
            applicable_patterns: vec!["ERC4626".to_string(), "vault".to_string(), "deposit".to_string(), "withdraw".to_string()],
            vulnerability_class: VulnerabilityClass::RoundingError,
            preconditions_template: vec!["amount > 0".to_string()],
        },
        InvariantTemplate {
            kind: InvariantKind::TotalSupplyInvariant,
            name: "totalSupply_consistency".to_string(),
            description: "Total supply must equal sum of all balances".to_string(),
            expression_template: "assertEq(target.totalSupply(), sumOfAllBalances)".to_string(),
            applicable_patterns: vec!["ERC20".to_string(), "mint".to_string(), "burn".to_string()],
            vulnerability_class: VulnerabilityClass::ArithmeticOverflow,
            preconditions_template: vec!["totalSupply > 0".to_string()],
        },
    ]
}

fn match_invariant_templates(contract: &SolidityContract) -> Vec<String> {
    let library = invariant_template_library();
    let contract_name_lower = contract.name.to_lowercase();
    let func_names: Vec<String> = contract
        .functions
        .iter()
        .map(|f| f.name.to_lowercase())
        .collect();
    let var_names: Vec<String> = contract
        .state_variables
        .iter()
        .map(|v| v.name.to_lowercase())
        .collect();
    let inherit_lower: Vec<String> = contract.inherits.iter().map(|i| i.to_lowercase()).collect();
    let all_text = format!(
        "{} {} {} {}",
        contract_name_lower,
        inherit_lower.join(" "),
        func_names.join(" "),
        var_names.join(" ")
    );

    library
        .iter()
        .filter(|t| {
            t.applicable_patterns
                .iter()
                .any(|p| all_text.contains(&p.to_lowercase()))
        })
        .map(|t| t.name.clone())
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SlitherFinding {
    pub detector: String,
    pub severity: String,
    pub confidence: String,
    pub description: String,
    pub first_markdown_line: Option<String>,
    pub elements: Vec<SlitherElement>,
}

impl SlitherFinding {
    pub fn to_vulnerability_class(&self) -> VulnerabilityClass {
        match self.detector.as_str() {
            "reentrancy-eth" | "reentrancy-no-eth" | "reentrancy-unlimited-gas" => {
                VulnerabilityClass::Reentrancy
            }
            "arithmetic" | "divide-before-multiply" => VulnerabilityClass::ArithmeticOverflow,
            "unchecked-lowlevel" | "unchecked-transfer" | "unchecked-return" => {
                VulnerabilityClass::UncheckedReturn
            }
            "controlled-delegatecall" => VulnerabilityClass::DelegatecallRisk,
            "tx-origin" => VulnerabilityClass::TxOriginAuth,
            "timestamp" | "block-timestamp" => VulnerabilityClass::TimestampDependence,
            "uninitialized-storage" | "uninitialized-local" => {
                VulnerabilityClass::UninitializedStorage
            }
            "protected-missing" | "missing-access-control" => VulnerabilityClass::AccessControl,
            "selfdestruct" => VulnerabilityClass::SelfDestruction,
            "front-running" | "race-condition" => VulnerabilityClass::FrontRunning,
            "oracle" | "price-manipulation" => VulnerabilityClass::OracleManipulation,
            "centralization" | "owner-always-win" => VulnerabilityClass::CentralizationRisk,
            s if s.contains("upgrade") || s.contains("proxy") => {
                VulnerabilityClass::UpgradeabilityRisk
            }
            _ => VulnerabilityClass::Custom(self.detector.clone()),
        }
    }

    pub fn to_web3_severity(&self) -> Web3Severity {
        match self.severity.to_lowercase().as_str() {
            "critical" | "high" => Web3Severity::High,
            "medium" => Web3Severity::Medium,
            "low" | "informational" => Web3Severity::Low,
            _ => Web3Severity::Informational,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SlitherElement {
    pub kind: String,
    pub name: Option<String>,
    pub contract_name: Option<String>,
    pub function_name: Option<String>,
    pub source_mapping: Option<SourceLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlitherOutput {
    pub findings: Vec<SlitherFinding>,
    pub success: bool,
    pub error: Option<String>,
}

impl SlitherOutput {
    pub fn parse_json(raw: &str) -> Result<Self, String> {
        let val: serde_json::Value = serde_json::from_str(raw)
            .map_err(|e| format!("Failed to parse Slither JSON: {}", e))?;

        let detectors = val
            .get("results")
            .and_then(|r| r.get("detectors"))
            .ok_or("No results.detectors in Slither output")?;

        let detectors_arr = detectors
            .as_array()
            .ok_or("results.detectors is not an array")?;

        let mut findings = Vec::new();
        for det in detectors_arr {
            let detector = det
                .get("check")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();

            let severity = det
                .get("impact")
                .and_then(|v| v.as_str())
                .unwrap_or("Informational")
                .to_string();

            let confidence = det
                .get("confidence")
                .and_then(|v| v.as_str())
                .unwrap_or("Medium")
                .to_string();

            let description = det
                .get("description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            let first_markdown_line = det
                .get("first_markdown_line")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            let elements_val = det
                .get("elements")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            let mut slither_elements = Vec::new();
            for elem in &elements_val {
                let kind = elem
                    .get("type")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown")
                    .to_string();
                let name = elem
                    .get("name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let contract_name = elem
                    .get("contract")
                    .and_then(|v| v.as_str())
                    .or_else(|| {
                        elem.get("type_specific_fields")
                            .and_then(|tsf| tsf.get("parent"))
                            .and_then(|p| p.get("name"))
                            .and_then(|n| n.as_str())
                    })
                    .map(|s| s.to_string());
                let function_name = elem
                    .get("type_specific_fields")
                    .and_then(|tsf| tsf.get("function"))
                    .and_then(|f| f.get("name"))
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string());

                let source_mapping = elem.get("source_mapping").and_then(|sm| {
                    let line = sm
                        .get("lines")
                        .and_then(|l| l.as_array())
                        .and_then(|arr| arr.first())
                        .and_then(|v| v.as_u64());
                    let file = sm.get("filename_relative").and_then(|v| v.as_str());
                    match (file, line) {
                        (Some(f), Some(l)) => Some(SourceLocation {
                            file: f.to_string(),
                            line: l as usize,
                        }),
                        _ => None,
                    }
                });

                slither_elements.push(SlitherElement {
                    kind,
                    name,
                    contract_name,
                    function_name,
                    source_mapping,
                });
            }

            findings.push(SlitherFinding {
                detector,
                severity,
                confidence,
                description,
                first_markdown_line,
                elements: slither_elements,
            });
        }

        Ok(Self {
            findings,
            success: true,
            error: None,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Web3Evidence {
    pub kind: Web3EvidenceKind,
    pub contract: String,
    pub function_name: Option<String>,
    pub description: String,
    pub source_location: Option<SourceLocation>,
    pub test_code: Option<String>,
    pub slither_detector: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum Web3EvidenceKind {
    StaticAnalysis,
    InvariantViolation,
    FuzzFailure,
    FormalVerification,
    ManualReview,
    GasEstimation,
    BytecodePattern,
}

impl Web3EvidenceKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::StaticAnalysis => "static_analysis",
            Self::InvariantViolation => "invariant_violation",
            Self::FuzzFailure => "fuzz_failure",
            Self::FormalVerification => "formal_verification",
            Self::ManualReview => "manual_review",
            Self::GasEstimation => "gas_estimation",
            Self::BytecodePattern => "bytecode_pattern",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web3Finding {
    pub id: String,
    pub classification: String,
    pub severity: Web3Severity,
    pub vulnerability_class: VulnerabilityClass,
    pub contract: String,
    pub function_name: Option<String>,
    pub description: String,
    pub remediation: String,
    pub evidence: Vec<Web3Evidence>,
    pub is_theoretical: bool,
    pub is_reachable: bool,
    pub invariant: Option<InvariantSpec>,
    pub slither_finding: Option<SlitherFinding>,
}

impl Web3Finding {
    pub fn new(
        id: impl Into<String>,
        contract: impl Into<String>,
        vuln_class: VulnerabilityClass,
        description: impl Into<String>,
        severity: Web3Severity,
    ) -> Self {
        let vuln_class_str = vuln_class.as_str();
        Self {
            id: id.into(),
            classification: vuln_class_str.to_string(),
            severity,
            vulnerability_class: vuln_class,
            contract: contract.into(),
            function_name: None,
            description: description.into(),
            remediation: String::new(),
            evidence: Vec::new(),
            is_theoretical: true,
            is_reachable: false,
            invariant: None,
            slither_finding: None,
        }
    }

    pub fn with_function(mut self, name: impl Into<String>) -> Self {
        self.function_name = Some(name.into());
        self
    }

    pub fn with_remediation(mut self, r: impl Into<String>) -> Self {
        self.remediation = r.into();
        self
    }

    pub fn with_evidence(mut self, e: Web3Evidence) -> Self {
        self.evidence.push(e);
        self
    }

    pub fn reachable(mut self) -> Self {
        self.is_reachable = true;
        self.is_theoretical = false;
        self
    }

    pub fn theoretical(mut self) -> Self {
        self.is_theoretical = true;
        self.is_reachable = false;
        self
    }

    pub fn with_invariant(mut self, inv: InvariantSpec) -> Self {
        self.invariant = Some(inv);
        self
    }

    pub fn with_slither_finding(mut self, sf: SlitherFinding) -> Self {
        self.slither_finding = Some(sf);
        self
    }

    pub fn to_finding_record(&self) -> FindingRecord {
        let state = if self.is_reachable {
            FindingState::Verified
        } else {
            FindingState::Hypothesis
        };

        FindingRecord {
            finding_id: self.id.clone(),
            scan_id: "web3".to_string(),
            fingerprint: format!("web3::{}::{}", self.contract, self.classification),
            classification: self.classification.clone(),
            vulnerability_class: self.vulnerability_class.as_str().to_string(),
            endpoint: format!(
                "{}::{}",
                self.contract,
                self.function_name.as_deref().unwrap_or("contract")
            ),
            object_id: String::new(),
            owner_profile: String::new(),
            tested_profile: String::new(),
            severity: self.severity.as_str().to_string(),
            score: match &self.severity {
                Web3Severity::Critical => 90,
                Web3Severity::High => 70,
                Web3Severity::Medium => 50,
                Web3Severity::Low => 30,
                Web3Severity::Informational => 10,
            },
            state,
            first_seen_run: "web3".to_string(),
            last_seen_run: "web3".to_string(),
            first_seen_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            last_seen_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            seen_count: 1,
            latest_artifacts: String::new(),
            latest_evidence_dir: String::new(),
            transitions: vec![],
            defense_classifications: vec![],
        }
    }
}

fn generate_remediation(vuln_class: &VulnerabilityClass) -> String {
    match vuln_class {
        VulnerabilityClass::Reentrancy => {
            "Use the checks-effects-interactions pattern, or implement a reentrancy guard (e.g., OpenZeppelin's ReentrancyGuard). Ensure state changes happen before external calls.".to_string()
        }
        VulnerabilityClass::AccessControl => {
            "Add proper access control modifiers (onlyOwner, onlyRole) to privileged functions. Use OpenZeppelin's Ownable or AccessControl libraries.".to_string()
        }
        VulnerabilityClass::ArithmeticOverflow | VulnerabilityClass::ArithmeticUnderflow => {
            "Use Solidity 0.8+ which has built-in overflow/underflow checks, or use SafeMath for Solidity <0.8.".to_string()
        }
        VulnerabilityClass::RoundingError => {
            "Round in favor of the protocol, not the user. Use mulDiv with rounding direction. Validate that rounding errors do not accumulate across operations.".to_string()
        }
        VulnerabilityClass::FrontRunning => {
            "Implement commit-reveal schemes, use slippage protection, or add minimum delay mechanisms. Consider Flashbots/MEV-protected submission.".to_string()
        }
        VulnerabilityClass::OracleManipulation => {
            "Use TWAP or multiple oracle sources. Validate oracle freshness, check for stale data, and implement circuit breakers for abnormal price deviations.".to_string()
        }
        VulnerabilityClass::FlashLoanAttack => {
            "Use time-locked operations, validate state changes over multiple blocks, or implement flash loan resistance checks (e.g., verify block.number consistency).".to_string()
        }
        VulnerabilityClass::SignatureReplay => {
            "Include nonce or deadline in signed messages. Use EIP-712 typed data signing. Never reuse signatures across chains or operations.".to_string()
        }
        VulnerabilityClass::UncheckedReturn => {
            "Check all return values from external calls, use require() or revert() on failures, or use SafeERC20 for token transfers.".to_string()
        }
        VulnerabilityClass::DenialOfService => {
            "Avoid unbounded loops over arrays that can be manipulated by external actors. Implement pull-over-push payment patterns.".to_string()
        }
        VulnerabilityClass::CentralizationRisk => {
            "Implement multi-sig or DAO governance for critical operations. Add timelocks for privileged actions. Minimize owner-controlled functionality.".to_string()
        }
        VulnerabilityClass::UpgradeabilityRisk => {
            "Use storage gaps for upgradeable contracts. Validate storage layout compatibility on upgrade. Consider UUPS over transparent proxy pattern for gas efficiency.".to_string()
        }
        VulnerabilityClass::IncorrectEquality => {
            "Avoid == comparisons on floating-point-like token amounts. Use >= or <= with appropriate margins for balance comparisons.".to_string()
        }
        VulnerabilityClass::UninitializedStorage => {
            "Initialize all storage variables in the constructor or initializer. Use the Initializable pattern for upgradeable contracts.".to_string()
        }
        VulnerabilityClass::DelegatecallRisk => {
            "Restrict delegatecall targets to trusted, immutable addresses. Validate implementation addresses before delegatecall. Never delegatecall to user-controlled addresses.".to_string()
        }
        VulnerabilityClass::TxOriginAuth => {
            "Replace tx.origin with msg.sender for authorization. Use msg.sender in all authentication checks.".to_string()
        }
        VulnerabilityClass::TimestampDependence => {
            "Do not rely on block.timestamp for critical logic. If timestamps are needed, use a broad acceptable range (e.g., 15-minute windows).".to_string()
        }
        VulnerabilityClass::SelfDestruction => {
            "Remove selfdestruct calls. If cleanup is needed, use a disabled state pattern instead of contract destruction.".to_string()
        }
        VulnerabilityClass::InsufficientValidation => {
            "Add comprehensive input validation for all external-facing functions. Validate amounts, addresses, and state preconditions before state changes.".to_string()
        }
        VulnerabilityClass::Custom(s) => format!("Review and address the identified issue: {}", s),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzConfig {
    pub runs: u32,
    pub max_test_time_secs: u64,
    pub max_depth: u32,
    pub seed: Option<String>,
    pub fuzz_runs: u32,
    pub invariant_runs: u32,
    pub timeout_per_test_secs: u64,
    pub fail_on_revert: bool,
    pub forge_path: Option<String>,
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            runs: 256,
            max_test_time_secs: 300,
            max_depth: 15,
            seed: None,
            fuzz_runs: 256,
            invariant_runs: 256,
            timeout_per_test_secs: 60,
            fail_on_revert: false,
            forge_path: None,
        }
    }
}

impl FuzzConfig {
    pub fn new(runs: u32, max_test_time_secs: u64) -> Self {
        Self {
            runs,
            max_test_time_secs,
            ..Self::default()
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzResult {
    pub test_name: String,
    pub contract: String,
    pub passed: bool,
    pub fuzz_runs: u32,
    pub duration_ms: u64,
    pub error_message: Option<String>,
    pub reproduction_steps: Option<Vec<String>>,
    pub gas_used: Option<u64>,
}

impl FuzzResult {
    pub fn passed(
        name: impl Into<String>,
        contract: impl Into<String>,
        runs: u32,
        duration_ms: u64,
    ) -> Self {
        Self {
            test_name: name.into(),
            contract: contract.into(),
            passed: true,
            fuzz_runs: runs,
            duration_ms,
            error_message: None,
            reproduction_steps: None,
            gas_used: None,
        }
    }

    pub fn failed(
        name: impl Into<String>,
        contract: impl Into<String>,
        runs: u32,
        duration_ms: u64,
        error: impl Into<String>,
        steps: Vec<String>,
    ) -> Self {
        Self {
            test_name: name.into(),
            contract: contract.into(),
            passed: false,
            fuzz_runs: runs,
            duration_ms,
            error_message: Some(error.into()),
            reproduction_steps: Some(steps),
            gas_used: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzRunResult {
    pub results: Vec<FuzzResult>,
    pub total_duration_ms: u64,
    pub passed_count: usize,
    pub failed_count: usize,
    pub command: String,
    pub timed_out: bool,
}

pub fn run_forge_fuzz(project_dir: &str, config: &FuzzConfig) -> Result<FuzzRunResult, String> {
    use std::process::Command;
    use std::time::Instant;

    let forge = config.forge_path.as_deref().unwrap_or("forge");
    let mut cmd = Command::new(forge);
    cmd.arg("test")
        .arg("--root")
        .arg(project_dir)
        .arg("-vv")
        .arg("--fuzz-runs")
        .arg(config.fuzz_runs.to_string())
        .arg("--invariant-runs")
        .arg(config.invariant_runs.to_string());

    if let Some(ref seed) = config.seed {
        cmd.arg("--fuzz-seed").arg(seed);
    }

    if config.fail_on_revert {
        cmd.arg("--revert");
    }

    let timeout = std::time::Duration::from_secs(config.max_test_time_secs);
    let start = Instant::now();
    let output = cmd
        .output()
        .map_err(|e| format!("Failed to execute forge: {e}"))?;
    let elapsed = start.elapsed();
    let timed_out = elapsed > timeout;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let full_output = format!("{stdout}\n{stderr}");

    let results = parse_forge_output(&full_output);
    let passed_count = results.iter().filter(|r| r.passed).count();
    let failed_count = results.iter().filter(|r| !r.passed).count();

    Ok(FuzzRunResult {
        command: format!("{:?}", cmd),
        total_duration_ms: elapsed.as_millis() as u64,
        results,
        passed_count,
        failed_count,
        timed_out,
    })
}

fn parse_forge_output(output: &str) -> Vec<FuzzResult> {
    let mut results = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        let has_pass = line.contains("[PASS]");
        let has_fail = line.contains("[FAIL") && line.contains(']');
        if !has_pass && !has_fail {
            continue;
        }
        let passed = has_pass;
        let test_name = line
            .split(|c: char| c == '[')
            .next()
            .unwrap_or("unknown")
            .trim()
            .to_string();
        let contract = if let Some(paren) = line.find(':') {
            line[..paren].trim().to_string()
        } else {
            String::new()
        };

        let runs = if let Some(runs_pos) = line.find("runs:") {
            let rest = &line[runs_pos + 6..];
            rest.split(|c: char| !c.is_ascii_digit())
                .next()
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(1)
        } else {
            1
        };

        let error_message = if !passed {
            Some("Test failed".to_string())
        } else {
            None
        };

        results.push(FuzzResult {
            test_name,
            contract,
            passed,
            fuzz_runs: runs,
            duration_ms: 0,
            error_message,
            reproduction_steps: None,
            gas_used: None,
        });
    }
    results
}

pub fn parse_forge_invariant_output(output: &str) -> Vec<FuzzResult> {
    let mut results = Vec::new();
    for line in output.lines() {
        let line = line.trim();
        if line.contains("[PASS]") || (line.contains("[FAIL") && line.contains(']')) {
            let passed = line.contains("[PASS]");
            let test_name = extract_invariant_test_name(line);
            let contract = String::new();
            let runs = if let Some(runs_pos) = line.find("runs:") {
                let rest = &line[runs_pos + 6..];
                rest.split(|c: char| !c.is_ascii_digit())
                    .next()
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(1)
            } else {
                1
            };

            let (error_message, reproduction_steps) = if !passed {
                let mut steps = Vec::new();
                if let Some(seq_pos) = line.find("Sequence:") {
                    let seq = &line[seq_pos + 9..];
                    steps = seq
                        .split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                (
                    Some("Invariant violation detected".to_string()),
                    if steps.is_empty() { None } else { Some(steps) },
                )
            } else {
                (None, None)
            };

            results.push(FuzzResult {
                test_name,
                contract,
                passed,
                fuzz_runs: runs,
                duration_ms: 0,
                error_message,
                reproduction_steps,
                gas_used: None,
            });
        }
    }
    results
}

pub fn extract_invariant_test_name(line: &str) -> String {
    if let Some(bracket) = line.find('[') {
        line[..bracket].trim().to_string()
    } else {
        line.split_whitespace()
            .next()
            .unwrap_or("unknown")
            .to_string()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExploitProof {
    pub id: String,
    pub vulnerability_class: VulnerabilityClass,
    pub contract: String,
    pub function_name: Option<String>,
    pub description: String,
    pub foundry_test_code: String,
    pub reproduction_steps: Vec<String>,
    pub invariant: Option<InvariantSpec>,
    pub severity: Web3Severity,
    pub is_confirmed: bool,
    pub slither_detector: Option<String>,
}

impl ExploitProof {
    pub fn from_invariant_violation(invariant: &InvariantSpec, contract: &str) -> Self {
        let severity = invariant.severity.clone();
        let vuln_class = invariant.vulnerability_class.clone();
        let test_code = invariant.to_foundry_test_code();

        Self {
            id: format!("exploit_{}", invariant.id),
            vulnerability_class: vuln_class,
            contract: contract.to_string(),
            function_name: invariant.function_selector.clone(),
            description: format!(
                "Invariant violation: {} - {}",
                invariant.name, invariant.description
            ),
            foundry_test_code: test_code,
            reproduction_steps: invariant.violation_sequence.clone().unwrap_or_default(),
            invariant: Some(invariant.clone()),
            severity,
            is_confirmed: false,
            slither_detector: None,
        }
    }

    pub fn confirmed(mut self) -> Self {
        self.is_confirmed = true;
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web3GeneratedTest {
    pub file_name: String,
    pub contract: String,
    pub invariant_id: String,
    pub vulnerability_class: String,
    pub severity: Web3Severity,
    pub status: InvariantStatus,
    pub foundry_command: String,
    pub code: String,
}

pub fn generate_foundry_proof_tests(result: &Web3AnalysisResult) -> Vec<Web3GeneratedTest> {
    result
        .invariants
        .iter()
        .map(|invariant| {
            let safe_id = invariant
                .id
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect::<String>();
            let file_name = format!("Baloncore_{}_{}.t.sol", invariant.contract, safe_id);
            Web3GeneratedTest {
                file_name,
                contract: invariant.contract.clone(),
                invariant_id: invariant.id.clone(),
                vulnerability_class: invariant.vulnerability_class.as_str().to_string(),
                severity: invariant.severity.clone(),
                status: invariant.status.clone(),
                foundry_command: format!(
                    "forge test --match-contract test_{} --match-test {}",
                    invariant.name, invariant.name
                ),
                code: invariant.to_foundry_test_code(),
            }
        })
        .collect()
}

pub fn render_web3_proof_manifest(tests: &[Web3GeneratedTest]) -> String {
    let mut md = String::new();
    md.push_str("# BALONCORE Web3 Proof Test Manifest\n\n");
    if tests.is_empty() {
        md.push_str("No generated Web3 proof tests are available.\n");
        return md;
    }
    md.push_str("| File | Contract | Class | Severity | Status | Command |\n");
    md.push_str("|------|----------|-------|----------|--------|---------|\n");
    for test in tests {
        md.push_str(&format!(
            "| `{}` | `{}` | `{}` | `{}` | `{:?}` | `{}` |\n",
            test.file_name,
            test.contract,
            test.vulnerability_class,
            test.severity.as_str(),
            test.status,
            test.foundry_command
        ));
    }
    md
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web3AnalysisResult {
    pub project: Web3Project,
    pub contract_inventory: Vec<ContractSummary>,
    pub findings: Vec<Web3Finding>,
    pub invariants: Vec<InvariantSpec>,
    pub exploit_proofs: Vec<ExploitProof>,
    pub slither_findings: Vec<SlitherFinding>,
    pub summary: Web3AnalysisSummary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractSummary {
    pub name: String,
    pub file: String,
    pub kind: String,
    pub function_count: usize,
    pub public_function_count: usize,
    pub state_changing_function_count: usize,
    pub payable_function_count: usize,
    pub is_erc20: bool,
    pub is_erc721: bool,
    pub is_erc1155: bool,
    pub is_upgradeable: bool,
    pub uses_oracle: bool,
    pub uses_delegation: bool,
    pub inherits_count: usize,
    pub vulnerability_patterns: Vec<String>,
}

impl From<&SolidityContract> for ContractSummary {
    fn from(c: &SolidityContract) -> Self {
        Self {
            name: c.name.clone(),
            file: c.file.clone(),
            kind: match c.kind {
                ContractKind::Contract => "contract",
                ContractKind::Interface => "interface",
                ContractKind::Library => "library",
                ContractKind::Abstract => "abstract",
            }
            .to_string(),
            function_count: c.functions.len(),
            public_function_count: c.public_functions().len(),
            state_changing_function_count: c.state_changing_functions().len(),
            payable_function_count: c.payable_functions().len(),
            is_erc20: c.is_erc20,
            is_erc721: c.is_erc721,
            is_erc1155: c.is_erc1155,
            is_upgradeable: c.is_upgradeable,
            uses_oracle: c.uses_oracle,
            uses_delegation: c.uses_delegation,
            inherits_count: c.inherits.len(),
            vulnerability_patterns: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Web3AnalysisSummary {
    pub project_name: String,
    pub project_kind: String,
    pub contract_count: usize,
    pub total_functions: usize,
    pub public_functions: usize,
    pub state_changing_functions: usize,
    pub payable_functions: usize,
    pub erc20_contracts: usize,
    pub erc721_contracts: usize,
    pub upgradeable_contracts: usize,
    pub oracle_contracts: usize,
    pub delegation_contracts: usize,
    pub slither_finding_count: usize,
    pub invariant_count: usize,
    pub finding_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub informational_count: usize,
    pub exploit_proof_count: usize,
    pub confirmed_exploit_count: usize,
}

pub fn analyze_web3_project(project: &mut Web3Project) -> Web3AnalysisResult {
    project.detect_all_patterns();

    let mut findings: Vec<Web3Finding> = Vec::new();
    let slither_findings: Vec<SlitherFinding> = Vec::new();
    let mut invariants: Vec<InvariantSpec> = Vec::new();
    let mut exploit_proofs: Vec<ExploitProof> = Vec::new();
    let mut finding_counter = 0u32;

    for contract in &project.contracts {
        let contract_patterns = determine_vulnerability_patterns(contract);
        let _contract_summary = ContractSummary::from(contract);
        let inv_template_names = match_invariant_templates(contract);
        let library = invariant_template_library();

        for template_name in &inv_template_names {
            if let Some(template) = library.iter().find(|t| &t.name == template_name) {
                let inv_id = format!("inv_{}_{}", contract.name, template.name);
                let expression = template
                    .expression_template
                    .replace("target", &contract.name);

                let invariant = InvariantSpec::new(
                    &inv_id,
                    template.kind.clone(),
                    &contract.name,
                    &expression,
                    template.vulnerability_class.clone(),
                );

                invariants.push(invariant);
            }
        }

        for pattern in &contract_patterns {
            let finding_id = format!("w3f_{:04}", finding_counter);
            finding_counter += 1;

            let vuln_class = pattern_to_vulnerability_class(pattern);
            let severity = vuln_class.to_severity();
            let remediation = generate_remediation(&vuln_class);

            let mut finding = Web3Finding::new(
                &finding_id,
                &contract.name,
                vuln_class,
                format!("{} detected in contract {}", pattern, contract.name),
                severity,
            )
            .theoretical()
            .with_remediation(remediation);

            if let Some(func) = pattern_function(pattern, contract) {
                finding = finding.with_function(func);
            }

            let evidence = Web3Evidence {
                kind: Web3EvidenceKind::StaticAnalysis,
                contract: contract.name.clone(),
                function_name: finding.function_name.clone(),
                description: format!("Pattern {} detected in {}", pattern, contract.name),
                source_location: contract.source_location.clone(),
                test_code: None,
                slither_detector: None,
            };
            finding = finding.with_evidence(evidence);

            findings.push(finding);
        }

        let payable_funcs = contract.payable_functions();
        for pf in &payable_funcs {
            if pf.modifiers.iter().all(|m| {
                m != "nonReentrant" && m != "onlyOwner" && m != "onlyRole" && !m.contains("auth")
            }) {
                let finding_id = format!("w3f_{:04}", finding_counter);
                finding_counter += 1;

                let mut finding = Web3Finding::new(
                    &finding_id,
                    &contract.name,
                    VulnerabilityClass::Reentrancy,
                    format!("Payable function {} lacks reentrancy protection", pf.name),
                    Web3Severity::High,
                )
                .with_function(&pf.name)
                .with_remediation(generate_remediation(&VulnerabilityClass::Reentrancy))
                .theoretical();

                finding = finding.with_evidence(Web3Evidence {
                    kind: Web3EvidenceKind::StaticAnalysis,
                    contract: contract.name.clone(),
                    function_name: Some(pf.name.clone()),
                    description: format!(
                        "Payable function {} without nonReentrant modifier",
                        pf.name
                    ),
                    source_location: pf.source_location.clone(),
                    test_code: None,
                    slither_detector: None,
                });

                findings.push(finding);
            }
        }
    }

    for inv in &invariants {
        if matches!(inv.status, InvariantStatus::Violated) {
            let proof = ExploitProof::from_invariant_violation(inv, &inv.contract);
            exploit_proofs.push(proof);
        }
    }

    let contract_inventory: Vec<ContractSummary> = project
        .contracts
        .iter()
        .map(|c| {
            let mut summary = ContractSummary::from(c);
            summary.vulnerability_patterns = determine_vulnerability_patterns(c);
            summary
        })
        .collect();

    let critical_count = findings
        .iter()
        .filter(|f| f.severity == Web3Severity::Critical)
        .count();
    let high_count = findings
        .iter()
        .filter(|f| f.severity == Web3Severity::High)
        .count();
    let medium_count = findings
        .iter()
        .filter(|f| f.severity == Web3Severity::Medium)
        .count();
    let low_count = findings
        .iter()
        .filter(|f| f.severity == Web3Severity::Low)
        .count();
    let informational_count = findings
        .iter()
        .filter(|f| f.severity == Web3Severity::Informational)
        .count();

    let summary = Web3AnalysisSummary {
        project_name: project.name.clone(),
        project_kind: project.kind.as_str().to_string(),
        contract_count: project.contracts.len(),
        total_functions: project.total_functions(),
        public_functions: project.public_functions().len(),
        state_changing_functions: project.state_changing_functions().len(),
        payable_functions: project.payable_functions().len(),
        erc20_contracts: project.contracts.iter().filter(|c| c.is_erc20).count(),
        erc721_contracts: project.contracts.iter().filter(|c| c.is_erc721).count(),
        upgradeable_contracts: project
            .contracts
            .iter()
            .filter(|c| c.is_upgradeable)
            .count(),
        oracle_contracts: project.contracts.iter().filter(|c| c.uses_oracle).count(),
        delegation_contracts: project
            .contracts
            .iter()
            .filter(|c| c.uses_delegation)
            .count(),
        slither_finding_count: slither_findings.len(),
        invariant_count: invariants.len(),
        finding_count: findings.len(),
        critical_count,
        high_count,
        medium_count,
        low_count,
        informational_count,
        exploit_proof_count: exploit_proofs.len(),
        confirmed_exploit_count: exploit_proofs.iter().filter(|p| p.is_confirmed).count(),
    };

    Web3AnalysisResult {
        project: project.clone(),
        contract_inventory,
        findings,
        invariants,
        exploit_proofs,
        slither_findings,
        summary,
    }
}

fn determine_vulnerability_patterns(contract: &SolidityContract) -> Vec<String> {
    let mut patterns = Vec::new();

    let external_funcs: Vec<&SolidityFunction> = contract
        .functions
        .iter()
        .filter(|f| f.visibility.is_accessible() && f.is_state_changing())
        .collect();

    let state_vars = &contract.state_variables;
    let func_names: Vec<&str> = contract.functions.iter().map(|f| f.name.as_str()).collect();
    let modifier_names: Vec<&str> = contract.modifiers.iter().map(|m| m.as_str()).collect();

    let has_delegatecall = func_names
        .iter()
        .any(|n| n.contains("delegatecall") || n.contains("delegate"));
    let has_tx_origin = func_names.iter().any(|n| {
        n.contains("txOrigin")
            || contract
                .functions
                .iter()
                .any(|f| f.parameters.iter().any(|p| p.name == "tx.origin"))
    });
    let has_unchecked_return = contract.functions.iter().any(|f| {
        f.is_state_changing()
            && !f
                .modifiers
                .iter()
                .any(|m| m.contains("safe") || m.contains("check"))
            && f.name.contains("transfer")
            || f.name.contains("send")
            || f.name.contains("call")
    });
    let has_payable_no_reentrancy = contract.payable_functions().iter().any(|f| {
        !f.modifiers
            .iter()
            .any(|m| m == "nonReentrant" || m == "nonReentrantView" || m.contains("lock"))
    });
    let has_uninitialized = state_vars
        .iter()
        .any(|v| !v.is_constant && !v.is_immutable && v.initial_value.is_none())
        && contract
            .functions
            .iter()
            .any(|f| f.name == "initialize" || f.name.contains("init") || f.name.contains("setUp"));
    let has_self_destruct = func_names
        .iter()
        .any(|n| n.contains("selfdestruct") || n.contains("selfDestruct") || n.contains("destroy"));
    let has_block_timestamp = func_names
        .iter()
        .any(|n| n.contains("timestamp") || n.contains("block.timestamp"));
    let has_assembly = modifier_names.iter().any(|m: &&str| m.contains("assembly"));
    let has_private_update = contract.functions.iter().any(|f| {
        f.is_state_changing()
            && f.visibility == FunctionVisibility::Private
            && f.name.contains("update")
            || f.name.contains("set")
    });

    if has_delegatecall {
        patterns.push("delegatecall_usage".to_string());
    }
    if has_tx_origin {
        patterns.push("tx_origin_usage".to_string());
    }
    if has_unchecked_return {
        patterns.push("unchecked_return_value".to_string());
    }
    if has_payable_no_reentrancy {
        patterns.push("missing_reentrancy_protection".to_string());
    }
    if has_uninitialized {
        patterns.push("uninitialized_state".to_string());
    }
    if has_self_destruct {
        patterns.push("selfdestruct_usage".to_string());
    }
    if has_block_timestamp {
        patterns.push("block_timestamp_usage".to_string());
    }
    if has_assembly {
        patterns.push("assembly_usage".to_string());
    }
    if has_private_update {
        patterns.push("private_state_update".to_string());
    }

    if contract.is_upgradeable {
        patterns.push("upgradeable_contract".to_string());
    }
    if contract.uses_oracle {
        patterns.push("oracle_dependency".to_string());
    }
    if contract.uses_delegation {
        patterns.push("delegation_pattern".to_string());
    }

    if contract.is_erc20 || contract.is_erc721 || contract.is_erc1155 {
        patterns.push("token_contract".to_string());
        if !contract.functions.iter().any(|f| {
            f.name.contains("pause")
                || f.name.contains("stop")
                || f.modifiers.iter().any(|m| m.contains("pause"))
        }) {
            patterns.push("missing_emergency_stop".to_string());
        }
    }

    if external_funcs.len() > 10 {
        patterns.push("large_attack_surface".to_string());
    }

    if !contract.inherits.is_empty() && !contract.is_erc20 && !contract.is_erc721 {
        patterns.push("complex_inheritance".to_string());
    }

    patterns
}

fn pattern_to_vulnerability_class(pattern: &str) -> VulnerabilityClass {
    match pattern {
        "delegatecall_usage" => VulnerabilityClass::DelegatecallRisk,
        "tx_origin_usage" => VulnerabilityClass::TxOriginAuth,
        "unchecked_return_value" => VulnerabilityClass::UncheckedReturn,
        "missing_reentrancy_protection" => VulnerabilityClass::Reentrancy,
        "uninitialized_state" => VulnerabilityClass::UninitializedStorage,
        "selfdestruct_usage" => VulnerabilityClass::SelfDestruction,
        "block_timestamp_usage" => VulnerabilityClass::TimestampDependence,
        "assembly_usage" => VulnerabilityClass::InsufficientValidation,
        "private_state_update" => VulnerabilityClass::AccessControl,
        "upgradeable_contract" => VulnerabilityClass::UpgradeabilityRisk,
        "oracle_dependency" => VulnerabilityClass::OracleManipulation,
        "delegation_pattern" => VulnerabilityClass::DelegatecallRisk,
        "token_contract" => VulnerabilityClass::ArithmeticOverflow,
        "missing_emergency_stop" => VulnerabilityClass::DenialOfService,
        "large_attack_surface" => VulnerabilityClass::AccessControl,
        "complex_inheritance" => VulnerabilityClass::InsufficientValidation,
        _ => VulnerabilityClass::Custom(pattern.to_string()),
    }
}

fn pattern_function(pattern: &str, contract: &SolidityContract) -> Option<String> {
    match pattern {
        "missing_reentrancy_protection" => {
            contract.payable_functions().first().map(|f| f.name.clone())
        }
        "tx_origin_usage" => contract
            .functions
            .iter()
            .find(|f| f.parameters.iter().any(|p| p.name == "tx.origin"))
            .map(|f| f.name.clone()),
        "unchecked_return_value" => contract
            .functions
            .iter()
            .find(|f| f.name.contains("transfer") || f.name.contains("send"))
            .map(|f| f.name.clone()),
        "selfdestruct_usage" => contract
            .functions
            .iter()
            .find(|f| f.name.contains("destroy"))
            .map(|f| f.name.clone()),
        _ => None,
    }
}

pub fn generate_invariants_for_project(project: &Web3Project) -> Vec<InvariantSpec> {
    let mut all_invariants = Vec::new();
    let library = invariant_template_library();

    for contract in &project.contracts {
        let matching = match_invariant_templates(contract);
        for template_name in matching {
            if let Some(template) = library.iter().find(|t| t.name == template_name) {
                let inv_id = format!("inv_{}_{}", contract.name, template.name);
                let expression = template
                    .expression_template
                    .replace("target", &contract.name);
                let invariant = InvariantSpec::new(
                    &inv_id,
                    template.kind.clone(),
                    &contract.name,
                    &expression,
                    template.vulnerability_class.clone(),
                )
                .with_precondition(
                    template
                        .preconditions_template
                        .first()
                        .cloned()
                        .unwrap_or_default(),
                );
                all_invariants.push(invariant);
            }
        }
    }

    all_invariants
}

pub fn ingest_slither_output(
    project: &mut Web3Project,
    slither_json: &str,
) -> Result<Vec<Web3Finding>, String> {
    let output = SlitherOutput::parse_json(slither_json)?;

    let mut findings = Vec::new();
    for (i, sf) in output.findings.iter().enumerate() {
        let contract_name = sf
            .elements
            .first()
            .and_then(|e| e.contract_name.clone())
            .unwrap_or_else(|| "unknown".to_string());

        let function_name = sf.elements.first().and_then(|e| e.function_name.clone());

        let vuln_class = sf.to_vulnerability_class();
        let severity = sf.to_web3_severity();
        let remediation = generate_remediation(&vuln_class);
        let mut finding = Web3Finding::new(
            format!("w3f_slither_{:04}", i),
            &contract_name,
            vuln_class.clone(),
            &sf.description,
            severity,
        )
        .with_remediation(remediation)
        .with_slither_finding(sf.clone())
        .theoretical();

        if let Some(func) = &function_name {
            finding = finding.with_function(func);
        }

        finding = finding.with_evidence(Web3Evidence {
            kind: Web3EvidenceKind::StaticAnalysis,
            contract: contract_name.clone(),
            function_name: function_name.clone(),
            description: format!("Slither detector: {}", sf.detector),
            source_location: sf.elements.first().and_then(|e| e.source_mapping.clone()),
            test_code: None,
            slither_detector: Some(sf.detector.clone()),
        });

        findings.push(finding);
    }

    for finding in &findings {
        project
            .contracts
            .iter_mut()
            .find(|c| c.name == finding.contract)
            .map(|_| {});
    }

    Ok(findings)
}

pub fn detect_project_kind(project_path: &str) -> Web3ProjectKind {
    let foundry_toml = std::path::Path::new(project_path).join("foundry.toml");
    let hardhat_config_ts = std::path::Path::new(project_path).join("hardhat.config.ts");
    let hardhat_config_js = std::path::Path::new(project_path).join("hardhat.config.js");
    let truffle_config = std::path::Path::new(project_path).join("truffle-config.js");
    let brownie_yaml = std::path::Path::new(project_path).join("brownie-config.yaml");

    if foundry_toml.exists() {
        Web3ProjectKind::Foundry
    } else if hardhat_config_ts.exists() || hardhat_config_js.exists() {
        Web3ProjectKind::Hardhat
    } else if truffle_config.exists() {
        Web3ProjectKind::Truffle
    } else if brownie_yaml.exists() {
        Web3ProjectKind::Brownie
    } else {
        Web3ProjectKind::Unknown
    }
}

pub fn apply_fuzz_results(result: &mut Web3AnalysisResult, fuzz_result: &FuzzRunResult) {
    for fuzz_test in &fuzz_result.results {
        if !fuzz_test.passed {
            if let Some(inv) = result.invariants.iter_mut().find(|i| {
                let test_name = format!("test_{}", i.name);
                fuzz_test.test_name.contains(&test_name) || fuzz_test.test_name.contains(&i.name)
            }) {
                inv.status = InvariantStatus::Violated;
                if let Some(ref steps) = fuzz_test.reproduction_steps {
                    inv.violation_sequence = Some(steps.clone());
                }
            }
            if let Some(finding) = result.findings.iter_mut().find(|f| {
                fuzz_test.test_name.contains(&f.id)
                    || f.vulnerability_class.as_str() == "reentrancy"
                    || f.vulnerability_class.as_str() == "access_control"
            }) {
                finding.is_theoretical = false;
                finding.is_reachable = true;
                if let Some(ref steps) = fuzz_test.reproduction_steps {
                    let step_desc = steps.join("; ");
                    finding.evidence.push(Web3Evidence {
                        kind: Web3EvidenceKind::FuzzFailure,
                        contract: finding.contract.clone(),
                        function_name: finding.function_name.clone(),
                        description: format!(
                            "Fuzz test {} confirmed the vulnerability. Reproduction: {}",
                            fuzz_test.test_name, step_desc
                        ),
                        source_location: None,
                        test_code: None,
                        slither_detector: None,
                    });
                }
            }
        }
    }
    for inv in result
        .invariants
        .iter()
        .filter(|i| i.status == InvariantStatus::Violated)
    {
        let proof = ExploitProof::from_invariant_violation(inv, &inv.contract);
        result.exploit_proofs.push(proof);
    }
    let confirmed = result.findings.iter().filter(|f| !f.is_theoretical).count();
    let exploited = result.exploit_proofs.len();
    result.summary.confirmed_exploit_count = confirmed + exploited;
}

pub fn run_fuzz_and_update(
    project_dir: &str,
    result: &mut Web3AnalysisResult,
    config: &FuzzConfig,
) -> Result<FuzzRunResult, String> {
    let fuzz_result = run_forge_fuzz(project_dir, config)?;
    apply_fuzz_results(result, &fuzz_result);
    Ok(fuzz_result)
}

pub fn render_web3_report(result: &Web3AnalysisResult) -> String {
    let mut report = String::new();

    report.push_str("# BALONCORE Web3 Smart Contract Analysis Report\n\n");

    report.push_str(&format!(
        "## Project: {} ({})\n\n",
        result.summary.project_name, result.summary.project_kind
    ));
    report.push_str(&format!("- Contracts: {}\n", result.summary.contract_count));
    report.push_str(&format!(
        "- Total functions: {}\n",
        result.summary.total_functions
    ));
    report.push_str(&format!(
        "- Public functions: {}\n",
        result.summary.public_functions
    ));
    report.push_str(&format!(
        "- State-changing functions: {}\n",
        result.summary.state_changing_functions
    ));
    report.push_str(&format!(
        "- Payable functions: {}\n",
        result.summary.payable_functions
    ));
    report.push_str(&format!(
        "- ERC-20 contracts: {}\n",
        result.summary.erc20_contracts
    ));
    report.push_str(&format!(
        "- ERC-721 contracts: {}\n",
        result.summary.erc721_contracts
    ));
    report.push_str(&format!(
        "- Upgradeable contracts: {}\n",
        result.summary.upgradeable_contracts
    ));
    report.push_str(&format!(
        "- Oracle-dependent contracts: {}\n",
        result.summary.oracle_contracts
    ));
    report.push_str(&format!(
        "- Delegation pattern contracts: {}\n",
        result.summary.delegation_contracts
    ));
    report.push_str("\n");

    report.push_str("## Findings Summary\n\n");
    report.push_str(&format!(
        "- **Critical**: {}\n",
        result.summary.critical_count
    ));
    report.push_str(&format!("- **High**: {}\n", result.summary.high_count));
    report.push_str(&format!("- **Medium**: {}\n", result.summary.medium_count));
    report.push_str(&format!("- **Low**: {}\n", result.summary.low_count));
    report.push_str(&format!(
        "- **Informational**: {}\n\n",
        result.summary.informational_count
    ));
    report.push_str(&format!(
        "- Slither findings: {}\n",
        result.summary.slither_finding_count
    ));
    report.push_str(&format!(
        "- Generated invariants: {}\n",
        result.summary.invariant_count
    ));
    report.push_str(&format!(
        "- Exploit proofs: {}\n\n",
        result.summary.exploit_proof_count
    ));

    if !result.contract_inventory.is_empty() {
        report.push_str("## Contract Inventory\n\n");
        report.push_str("| Contract | Type | Functions | Public | Payable | Patterns |\n");
        report.push_str("|----------|------|-----------|--------|---------|----------|\n");
        for ci in &result.contract_inventory {
            let patterns = if ci.vulnerability_patterns.is_empty() {
                "none".to_string()
            } else {
                ci.vulnerability_patterns.join(", ")
            };
            report.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} |\n",
                ci.name,
                ci.kind,
                ci.function_count,
                ci.public_function_count,
                ci.payable_function_count,
                patterns
            ));
        }
        report.push_str("\n");
    }

    if !result.findings.is_empty() {
        report.push_str("## Findings\n\n");
        for f in &result.findings {
            let reachable = if f.is_reachable {
                "reachable"
            } else {
                "theoretical"
            };
            report.push_str(&format!(
                "### [{}] {} - {} ({})\n\n",
                f.severity.as_str().to_uppercase(),
                f.id,
                f.classification,
                reachable
            ));
            report.push_str(&format!("**Contract:** {}\n\n", f.contract));
            if let Some(func) = &f.function_name {
                report.push_str(&format!("**Function:** {}\n\n", func));
            }
            report.push_str(&format!("{}\n\n", f.description));
            report.push_str(&format!("**Remediation:** {}\n\n", f.remediation));
            for ev in &f.evidence {
                report.push_str(&format!(
                    "- Evidence [{}]: {}\n",
                    ev.kind.as_str(),
                    ev.description
                ));
            }
            report.push_str("\n");
        }
    }

    if !result.invariants.is_empty() {
        report.push_str("## Generated Invariants\n\n");
        for inv in &result.invariants {
            report.push_str(&format!(
                "### {} ({})\n\n- Contract: {}\n- Expression: `{}`\n- Status: {:?}\n\n",
                inv.name,
                inv.kind.as_str(),
                inv.contract,
                inv.expression,
                inv.status
            ));
        }
    }

    if !result.exploit_proofs.is_empty() {
        report.push_str("## Exploit Proofs\n\n");
        for proof in &result.exploit_proofs {
            let confirmed = if proof.is_confirmed {
                "CONFIRMED"
            } else {
                "UNCONFIRMED"
            };
            report.push_str(&format!(
                "### {} [{}]\n\n- Vulnerability: {}\n- Contract: {}\n- Severity: {}\n\n{}\n\n",
                proof.id,
                confirmed,
                proof.vulnerability_class.as_str(),
                proof.contract,
                proof.severity.as_str(),
                proof.description
            ));
        }
    }

    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vault_contract() -> SolidityContract {
        SolidityContract::new("VulnerableVault", "VulnerableVault.sol")
            .with_kind(ContractKind::Contract)
            .with_function(
                SolidityFunction::new("deposit")
                    .with_visibility(FunctionVisibility::Public)
                    .with_state_mutability(StateMutability::Payable)
                    .with_parameter("amount", SolidityType::Uint256)
                    .with_return_type(SolidityType::Uint256)
                    .with_payable(),
            )
            .with_function(
                SolidityFunction::new("withdraw")
                    .with_visibility(FunctionVisibility::Public)
                    .with_parameter("shares", SolidityType::Uint256),
            )
            .with_function(
                SolidityFunction::new("totalSupply")
                    .with_visibility(FunctionVisibility::Public)
                    .with_state_mutability(StateMutability::View)
                    .with_return_type(SolidityType::Uint256),
            )
            .with_function(
                SolidityFunction::new("balanceOf")
                    .with_visibility(FunctionVisibility::Public)
                    .with_state_mutability(StateMutability::View)
                    .with_parameter("account", SolidityType::Address)
                    .with_return_type(SolidityType::Uint256),
            )
            .with_function(
                SolidityFunction::new("approve")
                    .with_visibility(FunctionVisibility::Public)
                    .with_parameter("spender", SolidityType::Address)
                    .with_parameter("amount", SolidityType::Uint256)
                    .with_return_type(SolidityType::Bool),
            )
            .with_function(
                SolidityFunction::new("allowance")
                    .with_visibility(FunctionVisibility::Public)
                    .with_state_mutability(StateMutability::View)
                    .with_parameter("owner", SolidityType::Address)
                    .with_parameter("spender", SolidityType::Address)
                    .with_return_type(SolidityType::Uint256),
            )
            .with_function(
                SolidityFunction::new("transfer")
                    .with_visibility(FunctionVisibility::Public)
                    .with_parameter("to", SolidityType::Address)
                    .with_parameter("amount", SolidityType::Uint256)
                    .with_return_type(SolidityType::Bool),
            )
            .with_function(
                SolidityFunction::new("transferFrom")
                    .with_visibility(FunctionVisibility::Public)
                    .with_parameter("from", SolidityType::Address)
                    .with_parameter("to", SolidityType::Address)
                    .with_parameter("amount", SolidityType::Uint256),
            )
            .with_state_variable(StorageVariable::new("totalShares", SolidityType::Uint256))
            .with_state_variable(
                StorageVariable::new("totalAssets", SolidityType::Uint256)
                    .with_visibility(FunctionVisibility::Public),
            )
            .with_state_variable(
                StorageVariable::new("_owner", SolidityType::Address)
                    .with_visibility(FunctionVisibility::Public),
            )
            .with_inherits("IERC20")
    }

    #[test]
    fn test_solidity_type_from_str() {
        assert_eq!(
            SolidityType::from_str_lossy("uint256"),
            SolidityType::Uint256
        );
        assert_eq!(
            SolidityType::from_str_lossy("address"),
            SolidityType::Address
        );
        assert_eq!(SolidityType::from_str_lossy("bool"), SolidityType::Bool);
        assert_eq!(SolidityType::from_str_lossy("string"), SolidityType::String);
        assert_eq!(
            SolidityType::from_str_lossy("bytes32"),
            SolidityType::Bytes32
        );
        assert_eq!(
            SolidityType::from_str_lossy("MyStruct"),
            SolidityType::Custom("MyStruct".to_string())
        );
        assert_eq!(SolidityType::from_str_lossy("uint8"), SolidityType::Uint8);
        assert_eq!(SolidityType::from_str_lossy("int256"), SolidityType::Int256);
    }

    #[test]
    fn test_solidity_type_predicates() {
        assert!(SolidityType::Uint256.is_integer());
        assert!(SolidityType::Uint256.is_unsigned());
        assert!(!SolidityType::Int256.is_unsigned());
        assert!(SolidityType::Address.is_integer() == false);
        assert!(SolidityType::Mapping(
            Box::new(SolidityType::Address),
            Box::new(SolidityType::Uint256)
        )
        .is_mapping());
    }

    #[test]
    fn test_function_visibility() {
        assert!(FunctionVisibility::Public.is_accessible());
        assert!(FunctionVisibility::External.is_accessible());
        assert!(!FunctionVisibility::Internal.is_accessible());
        assert!(!FunctionVisibility::Private.is_accessible());
    }

    #[test]
    fn test_state_mutability() {
        assert!(StateMutability::Pure.is_read_only());
        assert!(StateMutability::View.is_read_only());
        assert!(!StateMutability::NonPayable.is_read_only());
        assert!(!StateMutability::Payable.is_read_only());
    }

    #[test]
    fn test_solidity_function_signature() {
        let f = SolidityFunction::new("transfer")
            .with_parameter("to", SolidityType::Address)
            .with_parameter("amount", SolidityType::Uint256);
        assert_eq!(f.signature(), "transfer(address,uint256)");
    }

    #[test]
    fn test_solidity_function_predicates() {
        let f = SolidityFunction::new("deposit").with_payable();
        assert!(f.is_payable);
        assert!(f.is_state_changing());
        assert!(f.visibility.is_accessible());

        let g = SolidityFunction::new("balanceOf")
            .with_visibility(FunctionVisibility::Public)
            .with_state_mutability(StateMutability::View);
        assert!(g.is_accessor());
        assert!(!g.is_state_changing());
    }

    #[test]
    fn test_contract_pattern_detection_erc20() {
        let mut c = test_vault_contract();
        c.detect_patterns();
        assert!(c.is_erc20);
    }

    #[test]
    fn test_contract_pattern_detection_upgradeable() {
        let mut c = SolidityContract::new("MyProxy", "MyProxy.sol")
            .with_inherits("Initializable")
            .with_inherits("UUPSUpgradeable");
        c.detect_patterns();
        assert!(c.is_upgradeable);
    }

    #[test]
    fn test_contract_pattern_detection_oracle() {
        let mut c = SolidityContract::new("PriceConsumer", "PriceConsumer.sol")
            .with_inherits("AggregatorV3Interface")
            .with_function(
                SolidityFunction::new("latestRoundData")
                    .with_visibility(FunctionVisibility::Public)
                    .with_state_mutability(StateMutability::View),
            );
        c.detect_patterns();
        assert!(c.uses_oracle);
    }

    #[test]
    fn test_web3_project_construction() {
        let contract = test_vault_contract();
        let mut project =
            Web3Project::new("test-vault", "/path/to/vault", Web3ProjectKind::Foundry)
                .with_contract(contract);
        project.detect_all_patterns();

        assert_eq!(project.contracts.len(), 1);
        assert!(project.is_erc20());
        assert_eq!(project.total_functions(), 8);
        assert!(project.public_functions().len() >= 5);
    }

    #[test]
    fn test_invariant_template_library() {
        let library = invariant_template_library();
        assert!(library.len() >= 10);
        assert!(library
            .iter()
            .any(|t| matches!(t.kind, InvariantKind::ShareAccounting)));
        assert!(library
            .iter()
            .any(|t| matches!(t.kind, InvariantKind::ConservationOfAssets)));
        assert!(library
            .iter()
            .any(|t| matches!(t.kind, InvariantKind::AuthorizationCheck)));
    }

    #[test]
    fn test_invariant_spec_creation() {
        let inv = InvariantSpec::new(
            "inv_vault_share",
            InvariantKind::ShareAccounting,
            "VulnerableVault",
            "assertEq(target.totalShares(), target.totalAssets())",
            VulnerabilityClass::RoundingError,
        );
        assert_eq!(inv.kind, InvariantKind::ShareAccounting);
        assert_eq!(inv.severity, Web3Severity::Medium);
        assert_eq!(inv.status, InvariantStatus::Generated);
    }

    #[test]
    fn test_invariant_to_foundry_test() {
        let inv = InvariantSpec::new(
            "inv_vault_share",
            InvariantKind::ShareAccounting,
            "VulnerableVault",
            "assertEq(target.totalShares(), target.totalAssets())",
            VulnerabilityClass::RoundingError,
        );
        let code = inv.to_foundry_test_code();
        assert!(code.contains("VulnerableVault"));
        assert!(code.contains("test_share_accounting_VulnerableVault"));
        assert!(code.contains("../src/VulnerableVault.sol"));
        assert!(code.contains("pragma solidity"));
        assert!(code.contains("pragma solidity"));
    }

    #[test]
    fn test_vulnerability_class_severity() {
        assert_eq!(
            VulnerabilityClass::Reentrancy.to_severity(),
            Web3Severity::Critical
        );
        assert_eq!(
            VulnerabilityClass::AccessControl.to_severity(),
            Web3Severity::High
        );
        assert_eq!(
            VulnerabilityClass::RoundingError.to_severity(),
            Web3Severity::Medium
        );
        assert_eq!(
            VulnerabilityClass::TimestampDependence.to_severity(),
            Web3Severity::Low
        );
    }

    #[test]
    fn test_slither_output_parsing() {
        let json = r#"{
            "results": {
                "detectors": [
                    {
                        "check": "reentrancy-eth",
                        "impact": "High",
                        "confidence": "Medium",
                        "description": "Reentrancy in VulnerableVault.withdraw(uint256)",
                        "first_markdown_line": "VulnerableVault.withdraw(uint256)",
                        "elements": [
                            {
                                "type": "function",
                                "name": "withdraw",
                                "contract": "VulnerableVault",
                                "type_specific_fields": {
                                    "function": {
                                        "name": "withdraw"
                                    }
                                },
                                "source_mapping": {
                                    "filename_relative": "VulnerableVault.sol",
                                    "lines": [42]
                                }
                            }
                        ]
                    }
                ]
            }
        }"#;

        let output = SlitherOutput::parse_json(json).unwrap();
        assert_eq!(output.findings.len(), 1);
        assert_eq!(output.findings[0].detector, "reentrancy-eth");
        assert_eq!(
            output.findings[0].to_vulnerability_class(),
            VulnerabilityClass::Reentrancy
        );
        assert_eq!(output.findings[0].to_web3_severity(), Web3Severity::High);
        assert_eq!(
            output.findings[0].elements[0].contract_name,
            Some("VulnerableVault".to_string())
        );
        assert_eq!(
            output.findings[0].elements[0].source_mapping,
            Some(SourceLocation {
                file: "VulnerableVault.sol".to_string(),
                line: 42
            })
        );
    }

    #[test]
    fn test_slither_output_parsing_multiple_findings() {
        let json = r#"{
            "results": {
                "detectors": [
                    {
                        "check": "reentrancy-eth",
                        "impact": "High",
                        "confidence": "Medium",
                        "description": "Reentrancy in Vault.withdraw()",
                        "elements": [{"type": "function", "name": "withdraw", "contract": "Vault"}]
                    },
                    {
                        "check": "unchecked-lowlevel",
                        "impact": "Medium",
                        "confidence": "Medium",
                        "description": "Unchecked return value in Vault.transfer()",
                        "elements": [{"type": "function", "name": "transfer", "contract": "Vault"}]
                    }
                ]
            }
        }"#;

        let output = SlitherOutput::parse_json(json).unwrap();
        assert_eq!(output.findings.len(), 2);
        assert_eq!(output.findings[0].detector, "reentrancy-eth");
        assert_eq!(output.findings[1].detector, "unchecked-lowlevel");
        assert_eq!(
            output.findings[1].to_vulnerability_class(),
            VulnerabilityClass::UncheckedReturn
        );
    }

    #[test]
    fn test_determine_vulnerability_patterns() {
        let mut contract = SolidityContract::new("RiskyContract", "Risky.sol")
            .with_function(SolidityFunction::new("deposit").with_payable())
            .with_inherits("Initializable");
        contract.detect_patterns();

        let patterns = determine_vulnerability_patterns(&contract);
        assert!(patterns.contains(&"missing_reentrancy_protection".to_string()));
        assert!(patterns.contains(&"upgradeable_contract".to_string()));
    }

    #[test]
    fn test_analyze_web3_project() {
        let contract = test_vault_contract();
        let mut project =
            Web3Project::new("test-vault", "/path/to/vault", Web3ProjectKind::Foundry)
                .with_contract(contract);

        let result = analyze_web3_project(&mut project);

        assert!(result.findings.len() > 0);
        assert!(result.summary.contract_count > 0);
        assert!(result.summary.total_functions > 0);
        assert!(result.invariants.len() > 0);
        assert!(result.summary.erc20_contracts > 0);
    }

    #[test]
    fn test_generate_invariants_for_project() {
        let contract = test_vault_contract();
        let project = Web3Project::new("test-vault", "/path/to/vault", Web3ProjectKind::Foundry)
            .with_contract(contract);

        let invariants = generate_invariants_for_project(&project);
        assert!(invariants.len() > 0);
        assert!(invariants.iter().any(|i| matches!(
            i.kind,
            InvariantKind::ShareAccounting | InvariantKind::ConservationOfAssets
        )));
    }

    #[test]
    fn test_web3_finding_to_finding_record() {
        let finding = Web3Finding::new(
            "w3f_0001",
            "VulnerableVault",
            VulnerabilityClass::Reentrancy,
            "Reentrancy vulnerability",
            Web3Severity::Critical,
        )
        .reachable();

        let record = finding.to_finding_record();
        assert_eq!(record.finding_id, "w3f_0001");
        assert!(matches!(
            record.state,
            crate::lifecycle::FindingState::Verified
        ));
    }

    #[test]
    fn test_ingest_slither_output() {
        let contract = test_vault_contract();
        let mut project =
            Web3Project::new("test-vault", "/path/to/vault", Web3ProjectKind::Foundry)
                .with_contract(contract);

        let slither_json = r#"{
            "results": {
                "detectors": [
                    {
                        "check": "reentrancy-eth",
                        "impact": "High",
                        "confidence": "Medium",
                        "description": "Reentrancy in VulnerableVault.withdraw()",
                        "elements": [{"type": "function", "name": "withdraw", "contract": "VulnerableVault"}]
                    }
                ]
            }
        }"#;

        let findings = ingest_slither_output(&mut project, slither_json).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].vulnerability_class,
            VulnerabilityClass::Reentrancy
        );
    }

    #[test]
    fn test_render_web3_report() {
        let contract = test_vault_contract();
        let mut project =
            Web3Project::new("test-vault", "/path/to/vault", Web3ProjectKind::Foundry)
                .with_contract(contract);

        let result = analyze_web3_project(&mut project);
        let report = render_web3_report(&result);

        assert!(report.contains("# BALONCORE Web3 Smart Contract Analysis Report"));
        assert!(report.contains("test-vault"));
        assert!(report.contains("Findings Summary"));
        assert!(report.contains("Contract Inventory"));
    }

    #[test]
    fn test_exploit_proof_from_invariant() {
        let inv = InvariantSpec::new(
            "inv_vault_balance",
            InvariantKind::ConservationOfAssets,
            "VulnerableVault",
            "assertEq(target.totalAssets(), expected)",
            VulnerabilityClass::ArithmeticOverflow,
        )
        .with_status(InvariantStatus::Violated);

        let proof = ExploitProof::from_invariant_violation(&inv, "VulnerableVault");
        assert_eq!(
            proof.vulnerability_class,
            VulnerabilityClass::ArithmeticOverflow
        );
        assert!(!proof.is_confirmed);
        assert!(proof.foundry_test_code.contains("VulnerableVault"));
    }

    #[test]
    fn test_fuzz_config_defaults() {
        let config = FuzzConfig::default();
        assert_eq!(config.runs, 256);
        assert_eq!(config.max_test_time_secs, 300);
        assert_eq!(config.max_depth, 15);
    }

    #[test]
    fn test_generate_remediation() {
        assert!(generate_remediation(&VulnerabilityClass::Reentrancy)
            .contains("checks-effects-interactions"));
        assert!(generate_remediation(&VulnerabilityClass::AccessControl).contains("access control"));
        assert!(generate_remediation(&VulnerabilityClass::OracleManipulation).contains("TWAP"));
    }

    #[test]
    fn test_web3_finding_builder() {
        let f = Web3Finding::new(
            "w3f_001",
            "Vault",
            VulnerabilityClass::RoundingError,
            "Rounding error in share conversion",
            Web3Severity::Medium,
        )
        .with_function("convertToShares")
        .with_remediation("Round in favor of the protocol")
        .reachable();

        assert_eq!(f.id, "w3f_001");
        assert_eq!(f.contract, "Vault");
        assert_eq!(f.function_name, Some("convertToShares".to_string()));
        assert!(f.is_reachable);
        assert!(!f.is_theoretical);
        assert_eq!(f.severity, Web3Severity::Medium);
    }

    #[test]
    fn test_detect_project_kind_foundry() {
        let tmp_dir = std::env::temp_dir().join("baloncore_test_foundry");
        let _ = std::fs::create_dir_all(&tmp_dir);
        let foundry_toml = tmp_dir.join("foundry.toml");
        let _ = std::fs::write(&foundry_toml, "[profile.default]\nsrc = 'src'\n");

        let kind = detect_project_kind(tmp_dir.to_str().unwrap());
        assert_eq!(kind, Web3ProjectKind::Foundry);

        let _ = std::fs::remove_file(&foundry_toml);
        let _ = std::fs::remove_dir(&tmp_dir);
    }

    #[test]
    fn test_project_kinds() {
        assert_eq!(Web3ProjectKind::Foundry.as_str(), "foundry");
        assert_eq!(Web3ProjectKind::Hardhat.as_str(), "hardhat");
        assert_eq!(
            Web3ProjectKind::from_str_lossy("foundry"),
            Web3ProjectKind::Foundry
        );
        assert_eq!(
            Web3ProjectKind::from_str_lossy("hardhat"),
            Web3ProjectKind::Hardhat
        );
        assert_eq!(
            Web3ProjectKind::from_str_lossy("unknown"),
            Web3ProjectKind::Unknown
        );
    }

    #[test]
    fn test_invariant_status() {
        assert!(!InvariantStatus::Generated.is_terminal());
        assert!(!InvariantStatus::Fuzzing.is_terminal());
        assert!(InvariantStatus::Violated.is_terminal());
        assert!(InvariantStatus::Passed.is_terminal());
        assert!(InvariantStatus::Timeout.is_terminal());
    }

    #[test]
    fn test_contract_summary() {
        let contract = test_vault_contract();
        let summary = ContractSummary::from(&contract);
        assert_eq!(summary.name, "VulnerableVault");
        assert!(summary.function_count > 0);
        assert!(summary.public_function_count > 0);
    }

    #[test]
    fn test_storage_variable_predicates() {
        let v = StorageVariable::new("totalSupply", SolidityType::Uint256)
            .with_visibility(FunctionVisibility::Public);
        assert!(v.is_publicly_readable());

        let v_private = StorageVariable::new(
            "_balance",
            SolidityType::Mapping(
                Box::new(SolidityType::Address),
                Box::new(SolidityType::Uint256),
            ),
        );
        assert!(!v_private.is_publicly_readable());
    }

    #[test]
    fn test_web3_severity_round_trip() {
        assert_eq!(
            Web3Severity::from_str_lossy("critical"),
            Web3Severity::Critical
        );
        assert_eq!(Web3Severity::from_str_lossy("high"), Web3Severity::High);
        assert_eq!(Web3Severity::from_str_lossy("medium"), Web3Severity::Medium);
        assert_eq!(Web3Severity::from_str_lossy("low"), Web3Severity::Low);
        assert_eq!(
            Web3Severity::from_str_lossy("info"),
            Web3Severity::Informational
        );
    }

    #[test]
    fn test_parse_forge_output_pass_fail() {
        let output = r#"
Running 3 tests for test/Vault.t.sol:VaultTest
[PASS] test_deposit() (gas: 12345)
[PASS] test_withdraw() (gas: 67890)
[FAIL. Revert] test_reentrancy() (gas: 11111, runs: 256)
"#;
        let results = parse_forge_output(output);
        assert_eq!(results.len(), 3);
        assert!(results[0].passed);
        assert!(results[1].passed);
        assert!(!results[2].passed);
        assert_eq!(results[2].fuzz_runs, 256);
        assert!(results[2].error_message.is_some());
    }

    #[test]
    fn test_parse_forge_output_empty() {
        let output = "No tests found.";
        let results = parse_forge_output(output);
        assert!(results.is_empty());
    }

    #[test]
    fn test_parse_forge_invariant_output() {
        let output = "[FAIL. Revert] invariant_share_accounting() (runs: 256, calls: 1000) Sequence: deposit(100),withdraw(100),deposit(50)";
        let results = parse_forge_invariant_output(output);
        assert_eq!(results.len(), 1);
        assert!(!results[0].passed);
        assert_eq!(results[0].fuzz_runs, 256);
        assert!(results[0].reproduction_steps.is_some());
        let steps = results[0].reproduction_steps.as_ref().unwrap();
        assert_eq!(steps.len(), 3);
    }

    #[test]
    fn test_fuzz_config_default() {
        let config = FuzzConfig::default();
        assert_eq!(config.runs, 256);
        assert_eq!(config.fuzz_runs, 256);
        assert_eq!(config.invariant_runs, 256);
        assert_eq!(config.max_test_time_secs, 300);
        assert!(!config.fail_on_revert);
        assert!(config.forge_path.is_none());
        assert!(config.seed.is_none());
    }

    #[test]
    fn test_fuzz_result_passed() {
        let result = FuzzResult::passed("test_deposit", "Vault", 100, 50);
        assert!(result.passed);
        assert_eq!(result.test_name, "test_deposit");
        assert_eq!(result.contract, "Vault");
        assert!(result.error_message.is_none());
    }

    #[test]
    fn test_fuzz_result_failed() {
        let result = FuzzResult::failed(
            "test_reentrancy",
            "Vault",
            256,
            100,
            "Revert: EvmError: Revert",
            vec!["deposit(100)".to_string(), "withdraw(100)".to_string()],
        );
        assert!(!result.passed);
        assert!(result.error_message.is_some());
        assert!(result.reproduction_steps.is_some());
        assert_eq!(result.reproduction_steps.unwrap().len(), 2);
    }

    #[test]
    fn test_run_fuzz_and_update_marks_violations() {
        let contracts = crate::web3_parsers::parse_solidity_file(
            r#"
contract VulnerableVault {
    mapping(address => uint256) public shares;
    uint256 public totalShares;
    uint256 public totalAssets;
    uint256 public totalDebt;

    function deposit() public payable {
        shares[msg.sender] += msg.value;
        totalShares += msg.value;
        totalAssets += msg.value;
    }

    function withdraw(uint256 amount) public {
        uint256 userShares = shares[msg.sender];
        require(userShares >= amount, "Insufficient shares");
        shares[msg.sender] -= amount;
        totalShares -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        totalAssets -= amount;
    }

    function restrictedFunction() public {
        totalDebt = 100;
    }
}
"#,
            "VulnerableVault.sol",
        );
        assert!(!contracts.is_empty(), "Should parse at least one contract");
        let mut project = Web3Project::new("test", ".", Web3ProjectKind::Foundry);
        project.contracts = contracts;
        project.detect_all_patterns();
        let mut result = analyze_web3_project(&mut project);

        assert!(
            !result.invariants.is_empty(),
            "Should have at least one invariant"
        );

        let inv_name = result.invariants.first().unwrap().name.clone();
        let inv_contract = result.invariants.first().unwrap().contract.clone();
        let test_name = format!("test_{}", inv_name);

        let fuzz_result = FuzzRunResult {
            results: vec![FuzzResult::failed(
                test_name.clone(),
                inv_contract.clone(),
                256,
                100,
                "Invariant violation",
                vec!["deposit(100)".to_string(), "withdraw(100)".to_string()],
            )],
            total_duration_ms: 500,
            passed_count: 0,
            failed_count: 1,
            command: "forge test".to_string(),
            timed_out: false,
        };

        let before_proofs = result.exploit_proofs.len();
        apply_fuzz_results(&mut result, &fuzz_result);
        assert!(
            result.exploit_proofs.len() > before_proofs,
            "Should have at least one exploit proof after applying fuzz results"
        );
        let violated = result
            .invariants
            .iter()
            .filter(|i| i.status == InvariantStatus::Violated)
            .count();
        assert_eq!(violated, 1);
    }

    #[test]
    fn test_generate_foundry_proof_tests_from_invariants() {
        let mut project = Web3Project::new("test", ".", Web3ProjectKind::Foundry);
        project.contracts = vec![test_vault_contract()];
        project.detect_all_patterns();
        let result = analyze_web3_project(&mut project);
        let tests = generate_foundry_proof_tests(&result);
        assert!(!tests.is_empty());
        assert!(tests[0].file_name.ends_with(".t.sol"));
        assert!(tests[0].code.contains("forge-std/Test.sol"));
        assert!(tests[0].foundry_command.contains("forge test"));

        let manifest = render_web3_proof_manifest(&tests);
        assert!(manifest.contains("Web3 Proof Test Manifest"));
        assert!(manifest.contains(&tests[0].file_name));
    }
}
