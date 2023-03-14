#![cfg_attr(not(feature = "std"), no_std)]
use concordium_cis2::{Cis2Event, *};
use concordium_std::{collections::BTreeMap, *};

const TOKEN_ID_OVL: ContractTokenId = TokenIdUnit();

const DESIMALS: u8 = 6;
const MAX_SUPPLY: TokenAmountU64 = TokenAmountU64(1_000_000_000_000_000);

pub const NEW_ADMIN_EVENT_TAG: u8 = 0;

const SUPPORTS_STANDARDS: [StandardIdentifier<'static>; 2] =
    [CIS0_STANDARD_IDENTIFIER, CIS2_STANDARD_IDENTIFIER];

type ContractTokenId = TokenIdUnit;

type ContractTokenAmount = TokenAmountU64;

#[derive(Debug, Serial, DeserialWithState, Deletable, StateClone)]
#[concordium(state_parameter = "S")]
struct AddressState<S> {
    balance:   ContractTokenAmount,
    operators: StateSet<Address, S>,
}

#[derive(Debug, Serial, DeserialWithState, StateClone)]
#[concordium(state_parameter = "S")]
struct State<S: HasStateApi> {
    admin:        Address,
    paused:       bool,
    token:        StateMap<Address, AddressState<S>, S>,
    implementors: StateMap<StandardIdentifierOwned, Vec<ContractAddress>, S>,
    metadata_url: StateBox<concordium_cis2::MetadataUrl, S>,
    total_supply: TokenAmountU64,
}

#[derive(Serialize, SchemaType)]
struct MintParams {
    to:   Receiver,
    amount: ContractTokenAmount,
}

#[derive(Serialize, SchemaType)]
struct BurnParams {
    from:    Address,
    amount:   ContractTokenAmount,
}

#[derive(Serialize, SchemaType)]
struct TransferFromParams {
    from:   Address,
    to:     Receiver,
    amount: ContractTokenAmount,
}

#[derive(Debug, Serialize, SchemaType)]
struct SetImplementorsParams {
    id:           StandardIdentifierOwned,
    implementors: Vec<ContractAddress>,
}

#[derive(Debug, Serialize, SchemaType)]
struct UpgradeParams {
    module:  ModuleReference,
    migrate: Option<(OwnedEntrypointName, OwnedParameter)>,
}

#[derive(Serialize, SchemaType)]
struct ReturnBasicState {
    admin:        Address,
    paused:       bool,
    metadata_url: concordium_cis2::MetadataUrl,
}

#[derive(Serialize, SchemaType, Clone)]
struct SetMetadataUrlParams {
    /// The URL following the specification RFC1738.
    url:  String,
    hash: Option<Sha256>,
}

#[derive(Serialize, SchemaType)]
#[repr(transparent)]
struct SetPausedParams {
    paused: bool,
}

#[derive(Serial, SchemaType)]
#[repr(transparent)]
struct NewAdminEvent {
    new_admin: Address,
}

#[derive(Serial, SchemaType)]
struct TransferFromEvent {
    token_id: ContractTokenId,
    amount: ContractTokenAmount,
    from: Address,
    to: Address,
}

enum OvlEvent {
    NewAdmin(NewAdminEvent),
    Cis2Event(Cis2Event<ContractTokenId, ContractTokenAmount>),
}

impl Serial for OvlEvent {
    fn serial<W: Write>(&self, out: &mut W) -> Result<(), W::Err> {
        match self {
            OvlEvent::NewAdmin(event) => {
                out.write_u8(NEW_ADMIN_EVENT_TAG)?;
                event.serial(out)
            }
            OvlEvent::Cis2Event(event) => event.serial(out),
        }
    }
}

impl schema::SchemaType for OvlEvent {
    fn get_type() -> schema::Type {
        let mut event_map = BTreeMap::new();
        event_map.insert(
            NEW_ADMIN_EVENT_TAG,
            (
                "NewAdmin".to_string(),
                schema::Fields::Named(vec![(String::from("new_admin"), Address::get_type())]),
            ),
        );
        event_map.insert(
            TRANSFER_EVENT_TAG,
            (
                "Transfer".to_string(),
                schema::Fields::Named(vec![
                    (String::from("token_id"), ContractTokenId::get_type()),
                    (String::from("amount"), ContractTokenAmount::get_type()),
                    (String::from("from"), Address::get_type()),
                    (String::from("to"), Address::get_type()),
                ]),
            ),
        );
        event_map.insert(
            TRANSFER_FROM_EVENT_TAG,
            (
                "TransferFrom".to_string(),
                schema::Fields::Named(vec![
                    (String::from("token_id"), ContractTokenId::get_type()),
                    (String::from("amount"), ContractTokenAmount::get_type()),
                    (String::from("from"), Address::get_type()),
                    (String::from("to"), Address::get_type()),
                ]),
            ),
        );
        event_map.insert(
            MINT_EVENT_TAG,
            (
                "Mint".to_string(),
                schema::Fields::Named(vec![
                    (String::from("token_id"), ContractTokenId::get_type()),
                    (String::from("amount"), ContractTokenAmount::get_type()),
                    (String::from("owner"), Address::get_type()),
                ]),
            ),
        );
        event_map.insert(
            BURN_EVENT_TAG,
            (
                "Burn".to_string(),
                schema::Fields::Named(vec![
                    (String::from("token_id"), ContractTokenId::get_type()),
                    (String::from("amount"), ContractTokenAmount::get_type()),
                    (String::from("owner"), Address::get_type()),
                ]),
            ),
        );
        event_map.insert(
            UPDATE_OPERATOR_EVENT_TAG,
            (
                "UpdateOperator".to_string(),
                schema::Fields::Named(vec![
                    (String::from("update"), OperatorUpdate::get_type()),
                    (String::from("owner"), Address::get_type()),
                    (String::from("operator"), Address::get_type()),
                ]),
            ),
        );
        event_map.insert(
            TOKEN_METADATA_EVENT_TAG,
            (
                "TokenMetadata".to_string(),
                schema::Fields::Named(vec![
                    (String::from("token_id"), ContractTokenId::get_type()),
                    (String::from("metadata_url"), MetadataUrl::get_type()),
                ]),
            ),
        );
        schema::Type::TaggedEnum(event_map)
    }
}

/// The different errors the contract can produce.
#[derive(Serialize, Debug, PartialEq, Eq, Reject, SchemaType)]
enum CustomContractError {
    /// Failed parsing the parameter.
    #[from(ParseError)]
    ParseParams,
    /// Failed logging: Log is full.
    LogFull,
    /// Failed logging: Log is malformed.
    LogMalformed,
    /// Contract is paused.
    ContractPaused,
    /// Failed to invoke a contract.
    InvokeContractError,
    /// Failed to invoke a transfer.
    InvokeTransferError,
    /// Upgrade failed because the new module does not exist.
    FailedUpgradeMissingModule,
    /// Upgrade failed because the new module does not contain a contract with a
    /// matching name.
    FailedUpgradeMissingContract,
    /// Upgrade failed because the smart contract version of the module is not
    /// supported.
    FailedUpgradeUnsupportedModuleVersion,
    /// Token supply must be under max supply.
    OverMaxSupply
}

type ContractError = Cis2Error<CustomContractError>;

type ContractResult<A> = Result<A, ContractError>;

impl From<LogError> for CustomContractError {
    fn from(le: LogError) -> Self {
        match le {
            LogError::Full => Self::LogFull,
            LogError::Malformed => Self::LogMalformed,
        }
    }
}

impl<T> From<CallContractError<T>> for CustomContractError {
    fn from(_cce: CallContractError<T>) -> Self { Self::InvokeContractError }
}

impl From<TransferError> for CustomContractError {
    fn from(_te: TransferError) -> Self { Self::InvokeTransferError }
}

impl From<UpgradeError> for CustomContractError {
    #[inline(always)]
    fn from(ue: UpgradeError) -> Self {
        match ue {
            UpgradeError::MissingModule => Self::FailedUpgradeMissingModule,
            UpgradeError::MissingContract => Self::FailedUpgradeMissingContract,
            UpgradeError::UnsupportedModuleVersion => Self::FailedUpgradeUnsupportedModuleVersion,
        }
    }
}

impl From<CustomContractError> for ContractError {
    fn from(c: CustomContractError) -> Self { Cis2Error::Custom(c) }
}

impl<S: HasStateApi> State<S> {
    fn new(
        state_builder: &mut StateBuilder<S>,
        admin: Address,
        metadata_url: concordium_cis2::MetadataUrl,
    ) -> Self {
        State {
            admin,
            paused: false,
            token: state_builder.new_map(),
            implementors: state_builder.new_map(),
            metadata_url: state_builder.new_box(metadata_url),
            total_supply: TokenAmountU64(0)
        }
    }

    fn balance(
        &self,
        token_id: &ContractTokenId,
        address: &Address,
    ) -> ContractResult<ContractTokenAmount> {
        ensure_eq!(token_id, &TOKEN_ID_OVL, ContractError::InvalidTokenId);
        Ok(self.token.get(address).map(|s| s.balance).unwrap_or_else(|| 0u64.into()))
    }

    fn is_operator(&self, address: &Address, owner: &Address) -> bool {
        self.token
            .get(owner)
            .map(|address_state| address_state.operators.contains(address))
            .unwrap_or(false)
    }

    fn transfer(
        &mut self,
        token_id: &ContractTokenId,
        amount: ContractTokenAmount,
        from: &Address,
        to: &Address,
        state_builder: &mut StateBuilder<S>,
    ) -> ContractResult<()> {
        ensure_eq!(token_id, &TOKEN_ID_OVL, ContractError::InvalidTokenId);
        if amount == 0u64.into() {
            return Ok(());
        }
        {
            let mut from_state =
                self.token.get_mut(from).ok_or(ContractError::InsufficientFunds)?;
            ensure!(from_state.balance >= amount, ContractError::InsufficientFunds);
            from_state.balance -= amount;
        }
        let mut to_state = self.token.entry(*to).or_insert_with(|| AddressState {
            balance:   0u64.into(),
            operators: state_builder.new_set(),
        });
        to_state.balance += amount;

        Ok(())
    }

    fn add_operator(
        &mut self,
        owner: &Address,
        operator: &Address,
        state_builder: &mut StateBuilder<S>,
    ) {
        let mut owner_state = self.token.entry(*owner).or_insert_with(|| AddressState {
            balance:   0u64.into(),
            operators: state_builder.new_set(),
        });
        owner_state.operators.insert(*operator);
    }

    fn remove_operator(&mut self, owner: &Address, operator: &Address) {
        self.token.entry(*owner).and_modify(|address_state| {
            address_state.operators.remove(operator);
        });
    }

    fn mint(
        &mut self,
        token_id: &ContractTokenId,
        amount: ContractTokenAmount,
        owner: &Address,
        state_builder: &mut StateBuilder<S>,
    ) -> ContractResult<()> {
        ensure_eq!(token_id, &TOKEN_ID_OVL, ContractError::InvalidTokenId);
        let mut owner_state = self.token.entry(*owner).or_insert_with(|| AddressState {
            balance:   0u64.into(),
            operators: state_builder.new_set(),
        });

        ensure!(self.total_supply + amount <= MAX_SUPPLY, Cis2Error::Custom(CustomContractError::OverMaxSupply));
        self.total_supply += amount;
        owner_state.balance += amount;

        Ok(())
    }

    fn burn(
        &mut self,
        token_id: &ContractTokenId,
        amount: ContractTokenAmount,
        owner: &Address,
    ) -> ContractResult<()> {
        ensure_eq!(token_id, &TOKEN_ID_OVL, ContractError::InvalidTokenId);
        if amount == 0u64.into() {
            return Ok(());
        }

        let mut from_state = self.token.get_mut(owner).ok_or(ContractError::InsufficientFunds)?;
        ensure!(from_state.balance >= amount, ContractError::InsufficientFunds);
        self.total_supply -= amount;
        from_state.balance -= amount;

        Ok(())
    }

    fn have_implementors(&self, std_id: &StandardIdentifierOwned) -> SupportResult {
        if let Some(addresses) = self.implementors.get(std_id) {
            SupportResult::SupportBy(addresses.to_vec())
        } else {
            SupportResult::NoSupport
        }
    }

    fn set_implementors(
        &mut self,
        std_id: StandardIdentifierOwned,
        implementors: Vec<ContractAddress>,
    ) {
        self.implementors.insert(std_id, implementors);
    }
}

#[init(
    contract = "cis2_OVL",
    enable_logger,
    parameter = "SetMetadataUrlParams",
    event = "OvlEvent"
)]
fn contract_init<S: HasStateApi>(
    ctx: &impl HasInitContext,
    state_builder: &mut StateBuilder<S>,
    logger: &mut impl HasLogger,
) -> InitResult<State<S>> {
    let params: SetMetadataUrlParams = ctx.parameter_cursor().get()?;
    let invoker = Address::Account(ctx.init_origin());

    let metadata_url = MetadataUrl {
        url:  params.url.clone(),
        hash: params.hash,
    };

    let state = State::new(state_builder, invoker, metadata_url.clone());

    logger.log(&OvlEvent::Cis2Event(Cis2Event::Mint(MintEvent {
        token_id: TOKEN_ID_OVL,
        amount:   ContractTokenAmount::from(0u64),
        owner:    invoker,
    })))?;

    logger.log(&OvlEvent::Cis2Event(Cis2Event::TokenMetadata::<_, ContractTokenAmount>(
        TokenMetadataEvent {
            token_id: TOKEN_ID_OVL,
            metadata_url,
        },
    )))?;

    logger.log(&OvlEvent::NewAdmin(NewAdminEvent {
        new_admin: invoker,
    }))?;

    Ok(state)
}

#[receive(
    contract = "cis2_OVL",
    name = "mint",
    parameter = "MintParams",
    error = "ContractError",
    enable_logger,
    mutable
)]
fn contract_mint<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<State<S>, StateApiType = S>,
    logger: &mut impl HasLogger,
) -> ContractResult<()> {
    ensure!(!host.state().paused, ContractError::Custom(CustomContractError::ContractPaused));

    let params: MintParams = ctx.parameter_cursor().get()?;
    let sender = ctx.sender();
    ensure_eq!(ctx.sender(), host.state().admin, ContractError::Unauthorized);

    let receive_address = params.to.address();

    let (state, state_builder) = host.state_and_builder();

    state.mint(&TOKEN_ID_OVL, params.amount, &receive_address, state_builder)?;

    logger.log(&Cis2Event::Mint(MintEvent {
        token_id: TOKEN_ID_OVL,
        amount:   ContractTokenAmount::from(params.amount),
        owner:    sender,
    }))?;

    if sender != receive_address {
        logger.log(&Cis2Event::Transfer(TransferEvent {
            token_id: TOKEN_ID_OVL,
            amount:   ContractTokenAmount::from(params.amount),
            from:     sender,
            to:       receive_address,
        }))?;
    }

    Ok(())
}

#[receive(
    contract = "cis2_OVL",
    name = "burn",
    parameter = "BurnParams",
    error = "ContractError",
    enable_logger,
    mutable
)]
fn contract_burn<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<State<S>, StateApiType = S>,
    logger: &mut impl HasLogger,
) -> ContractResult<()> {
    ensure!(!host.state().paused, ContractError::Custom(CustomContractError::ContractPaused));

    let params: BurnParams = ctx.parameter_cursor().get()?;
    let sender = ctx.sender();
    let state = host.state_mut();
    ensure!(
        sender == params.from || state.is_operator(&sender, &params.from),
        ContractError::Unauthorized
    );

    state.burn(&TOKEN_ID_OVL, params.amount, &params.from)?;

    logger.log(&Cis2Event::Burn(BurnEvent {
        token_id: TOKEN_ID_OVL,
        amount:   params.amount,
        owner:    params.from,
    }))?;

    Ok(())
}

#[receive(
    contract = "cis2_OVL",
    name = "updateAdmin",
    parameter = "Address",
    error = "ContractError",
    enable_logger,
    mutable
)]
fn contract_update_admin<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<State<S>, StateApiType = S>,
    logger: &mut impl HasLogger,
) -> ContractResult<()> {
    ensure_eq!(ctx.sender(), host.state().admin, ContractError::Unauthorized);

    let new_admin = ctx.parameter_cursor().get()?;

    host.state_mut().admin = new_admin;

    logger.log(&OvlEvent::NewAdmin(NewAdminEvent {
        new_admin,
    }))?;

    Ok(())
}

#[receive(
    contract = "cis2_OVL",
    name = "setPaused",
    parameter = "SetPausedParams",
    error = "ContractError",
    mutable
)]
fn contract_set_paused<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<State<S>, StateApiType = S>,
) -> ContractResult<()> {
    ensure_eq!(ctx.sender(), host.state().admin, ContractError::Unauthorized);

    let params: SetPausedParams = ctx.parameter_cursor().get()?;

    host.state_mut().paused = params.paused;

    Ok(())
}

/// Update the metadata URL in this smart contract instance.
///
/// It rejects if:
/// - Sender is not the admin of the contract instance.
/// - It fails to parse the parameter.
#[receive(
    contract = "cis2_OVL",
    name = "setMetadataUrl",
    parameter = "SetMetadataUrlParams",
    error = "ContractError",
    enable_logger,
    mutable
)]
fn contract_state_set_metadata_url<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<State<S>, StateApiType = S>,
    logger: &mut impl HasLogger,
) -> ContractResult<()> {
    ensure_eq!(ctx.sender(), host.state().admin, ContractError::Unauthorized);

    let params: SetMetadataUrlParams = ctx.parameter_cursor().get()?;

    let metadata_url = MetadataUrl {
        url:  params.url.clone(),
        hash: params.hash,
    };

    *host.state_mut().metadata_url = metadata_url.clone();

    logger.log(&OvlEvent::Cis2Event(Cis2Event::TokenMetadata::<_, ContractTokenAmount>(
        TokenMetadataEvent {
            token_id: TOKEN_ID_OVL,
            metadata_url,
        },
    )))?;

    Ok(())
}

type TransferParameter = TransferParams<ContractTokenId, ContractTokenAmount>;

#[receive(
    contract = "cis2_OVL",
    name = "transfer",
    parameter = "TransferParameter",
    error = "ContractError",
    enable_logger,
    mutable
)]
fn contract_transfer<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<State<S>, StateApiType = S>,
    logger: &mut impl HasLogger,
) -> ContractResult<()> {
    ensure!(!host.state().paused, ContractError::Custom(CustomContractError::ContractPaused));

    let TransferParams(transfers): TransferParameter = ctx.parameter_cursor().get()?;
    let sender = ctx.sender();

    for Transfer {
        token_id,
        amount,
        from,
        to,
        data,
    } in transfers
    {
        let (state, builder) = host.state_and_builder();
        ensure!(from == sender || state.is_operator(&sender, &from), ContractError::Unauthorized);
        let to_address = to.address();
        state.transfer(&token_id, amount, &from, &to_address, builder)?;

        logger.log(&OvlEvent::Cis2Event(Cis2Event::Transfer(TransferEvent {
            token_id,
            amount,
            from,
            to: to_address,
        })))?;

        // If the receiver is a contract: invoke the receive hook function.
        if let Receiver::Contract(address, function) = to {
            let parameter = OnReceivingCis2Params {
                token_id,
                amount,
                from,
                data,
            };
            host.invoke_contract(
                &address,
                &parameter,
                function.as_entrypoint_name(),
                Amount::zero(),
            )?;
        }
    }
    Ok(())
}

#[receive(
    contract = "cis2_OVL",
    name = "updateOperator",
    parameter = "UpdateOperatorParams",
    error = "ContractError",
    enable_logger,
    mutable
)]
fn contract_update_operator<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<State<S>, StateApiType = S>,
    logger: &mut impl HasLogger,
) -> ContractResult<()> {
    ensure!(!host.state().paused, ContractError::Custom(CustomContractError::ContractPaused));

    let UpdateOperatorParams(params) = ctx.parameter_cursor().get()?;
    let sender = ctx.sender();

    let (state, state_builder) = host.state_and_builder();
    for param in params {
        match param.update {
            OperatorUpdate::Add => state.add_operator(&sender, &param.operator, state_builder),
            OperatorUpdate::Remove => state.remove_operator(&sender, &param.operator),
        }

        logger.log(&OvlEvent::Cis2Event(
            Cis2Event::<ContractTokenId, ContractTokenAmount>::UpdateOperator(
                UpdateOperatorEvent {
                    owner:    sender,
                    operator: param.operator,
                    update:   param.update,
                },
            ),
        ))?;
    }

    Ok(())
}

type ContractBalanceOfQueryParams = BalanceOfQueryParams<ContractTokenId>;

type ContractBalanceOfQueryResponse = BalanceOfQueryResponse<ContractTokenAmount>;

#[receive(
    contract = "cis2_OVL",
    name = "balanceOf",
    parameter = "ContractBalanceOfQueryParams",
    return_value = "ContractBalanceOfQueryResponse",
    error = "ContractError"
)]
fn contract_balance_of<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &impl HasHost<State<S>, StateApiType = S>,
) -> ContractResult<ContractBalanceOfQueryResponse> {
    let params: ContractBalanceOfQueryParams = ctx.parameter_cursor().get()?;
    let mut response = Vec::with_capacity(params.queries.len());
    for query in params.queries {
        let amount = host.state().balance(&query.token_id, &query.address)?;
        response.push(amount);
    }
    let result = ContractBalanceOfQueryResponse::from(response);
    Ok(result)
}

#[receive(
    contract = "cis2_OVL",
    name = "operatorOf",
    parameter = "OperatorOfQueryParams",
    return_value = "OperatorOfQueryResponse",
    error = "ContractError"
)]
fn contract_operator_of<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &impl HasHost<State<S>, StateApiType = S>,
) -> ContractResult<OperatorOfQueryResponse> {
    let params: OperatorOfQueryParams = ctx.parameter_cursor().get()?;
    let mut response = Vec::with_capacity(params.queries.len());
    for query in params.queries {
        let is_operator = host.state().is_operator(&query.address, &query.owner);
        response.push(is_operator);
    }
    let result = OperatorOfQueryResponse::from(response);
    Ok(result)
}

pub type ContractTokenMetadataQueryParams = TokenMetadataQueryParams<ContractTokenId>;

#[receive(
    contract = "cis2_OVL",
    name = "tokenMetadata",
    parameter = "ContractTokenMetadataQueryParams",
    return_value = "TokenMetadataQueryResponse",
    error = "ContractError"
)]
fn contract_token_metadata<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &impl HasHost<State<S>, StateApiType = S>,
) -> ContractResult<TokenMetadataQueryResponse> {
    let params: ContractTokenMetadataQueryParams = ctx.parameter_cursor().get()?;

    let mut response = Vec::with_capacity(params.queries.len());
    for token_id in params.queries {
        ensure_eq!(token_id, TOKEN_ID_OVL, ContractError::InvalidTokenId);

        response.push(host.state().metadata_url.clone());
    }
    let result = TokenMetadataQueryResponse::from(response);
    Ok(result)
}

#[receive(
    contract = "cis2_OVL",
    name = "view",
    return_value = "ReturnBasicState",
    error = "ContractError"
)]
fn contract_view<S: HasStateApi>(
    _ctx: &impl HasReceiveContext,
    host: &impl HasHost<State<S>, StateApiType = S>,
) -> ContractResult<ReturnBasicState> {
    let state = ReturnBasicState {
        admin:        host.state().admin,
        paused:       host.state().paused,
        metadata_url: host.state().metadata_url.clone(),
    };
    Ok(state)
}

#[receive(
    contract = "cis2_OVL",
    name = "supports",
    parameter = "SupportsQueryParams",
    return_value = "SupportsQueryResponse",
    error = "ContractError"
)]
fn contract_supports<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &impl HasHost<State<S>, StateApiType = S>,
) -> ContractResult<SupportsQueryResponse> {
    let params: SupportsQueryParams = ctx.parameter_cursor().get()?;
    let mut response = Vec::with_capacity(params.queries.len());
    for std_id in params.queries {
        if SUPPORTS_STANDARDS.contains(&std_id.as_standard_identifier()) {
            response.push(SupportResult::Support);
        } else {
            response.push(host.state().have_implementors(&std_id));
        }
    }
    let result = SupportsQueryResponse::from(response);
    Ok(result)
}

#[receive(
    contract = "cis2_OVL",
    name = "setImplementors",
    parameter = "SetImplementorsParams",
    error = "ContractError",
    mutable
)]
fn contract_set_implementor<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<State<S>, StateApiType = S>,
) -> ContractResult<()> {
    ensure_eq!(ctx.sender(), host.state().admin, ContractError::Unauthorized);
    let params: SetImplementorsParams = ctx.parameter_cursor().get()?;
    host.state_mut().set_implementors(params.id, params.implementors);
    Ok(())
}

#[receive(
    contract = "cis2_OVL",
    name = "upgrade",
    parameter = "UpgradeParams",
    error = "ContractError",
    mutable
)]
fn contract_upgrade<S: HasStateApi>(
    ctx: &impl HasReceiveContext,
    host: &mut impl HasHost<State<S>, StateApiType = S>,
) -> ContractResult<()> {
    ensure_eq!(ctx.sender(), host.state().admin, ContractError::Unauthorized);
    let params: UpgradeParams = ctx.parameter_cursor().get()?;
    host.upgrade(params.module)?;
    if let Some((func, parameters)) = params.migrate {
        host.invoke_contract_raw(
            &ctx.self_address(),
            parameters.as_parameter(),
            func.as_entrypoint_name(),
            Amount::zero(),
        )?;
    }
    Ok(())
}

#[receive(
    contract = "cis2_OVL",
    name = "decimals",
    return_value = "u8",
    error = "ContractError"
)]
fn contract_decimals<S: HasStateApi>(
    _ctx: &impl HasReceiveContext,
    _host: &impl HasHost<State<S>, StateApiType = S>,
) -> ContractResult<u8> {
    Ok(DESIMALS)
}

#[receive(
    contract = "cis2_OVL",
    name = "maxSupply",
    return_value = "TokenAmountU64",
    error = "ContractError"
)]
fn contract_max_supply<S: HasStateApi>(
    _ctx: &impl HasReceiveContext,
    _host: &impl HasHost<State<S>, StateApiType = S>,
) -> ContractResult<TokenAmountU64> {
    Ok(MAX_SUPPLY)
}

#[receive(
    contract = "cis2_OVL",
    name = "totalSupply",
    return_value = "TokenAmountU64",
    error = "ContractError"
)]
fn contract_total_supply<S: HasStateApi>(
    _ctx: &impl HasReceiveContext,
    host: &impl HasHost<State<S>, StateApiType = S>,
) -> ContractResult<TokenAmountU64> {
    Ok(host.state().total_supply)
}

#[concordium_cfg_test]
mod tests {
    use super::*;
    use test_infrastructure::*;

    const ACCOUNT_0: AccountAddress = AccountAddress([0u8; 32]);
    const ADDRESS_0: Address = Address::Account(ACCOUNT_0);
    const ACCOUNT_1: AccountAddress = AccountAddress([1u8; 32]);
    const ADDRESS_1: Address = Address::Account(ACCOUNT_1);
    const ADMIN_ACCOUNT: AccountAddress = AccountAddress([2u8; 32]);
    const ADMIN_ADDRESS: Address = Address::Account(ADMIN_ACCOUNT);
    const NEW_ADMIN_ACCOUNT: AccountAddress = AccountAddress([3u8; 32]);
    const NEW_ADMIN_ADDRESS: Address = Address::Account(NEW_ADMIN_ACCOUNT);

    // The metadata url for the wCCD token.
    const INITIAL_TOKEN_METADATA_URL: &str = "https://some.example/token/wccd";

    /// Test helper function which creates a contract state where ADDRESS_0 owns
    /// 400 tokens.
    fn initial_state<S: HasStateApi>(state_builder: &mut StateBuilder<S>) -> State<S> {
        // Set up crypto primitives to hash the document.
        let crypto_primitives = TestCryptoPrimitives::new();
        // The hash of the document stored at the above URL.
        let initial_metadata_hash: Sha256 =
            crypto_primitives.hash_sha2_256("document".as_bytes()).0;

        let metadata_url = concordium_cis2::MetadataUrl {
            url:  INITIAL_TOKEN_METADATA_URL.to_string(),
            hash: Some(initial_metadata_hash),
        };

        let mut state = State::new(state_builder, ADMIN_ADDRESS, metadata_url);
        state
            .mint(&TOKEN_ID_OVL, 400u64.into(), &ADDRESS_0, state_builder)
            .expect_report("Failed to setup state");
        state
    }

    /// Test initialization succeeds and the tokens are owned by the contract
    /// instantiator and the appropriate events are logged.
    #[concordium_test]
    fn test_init() {
        // Set up the context
        let mut ctx = TestInitContext::empty();
        ctx.set_init_origin(ACCOUNT_0);

        let mut logger = TestLogger::init();
        let mut builder = TestStateBuilder::new();

        // Set up crypto primitives to hash the document.
        let crypto_primitives = TestCryptoPrimitives::new();
        // The hash of the document stored at the above URL.
        let initial_metadata_hash: Sha256 =
            crypto_primitives.hash_sha2_256("document".as_bytes()).0;

        // Set up the parameter.
        let parameter = SetMetadataUrlParams {
            url:  String::from(INITIAL_TOKEN_METADATA_URL),
            hash: Some(initial_metadata_hash),
        };
        let parameter_bytes = to_bytes(&parameter);
        ctx.set_parameter(&parameter_bytes);

        // Call the contract function.
        let result = contract_init(&ctx, &mut builder, &mut logger);

        // Check the result
        let state = result.expect_report("Contract initialization failed");

        // Check the state
        claim_eq!(state.token.iter().count(), 0, "Only one token is initialized");
        let balance0 =
            state.balance(&TOKEN_ID_OVL, &ADDRESS_0).expect_report("Token is expected to exist");
        claim_eq!(
            balance0,
            0u64.into(),
            "No initial tokens are owned by the contract instantiator"
        );

        // Check the logs
        claim_eq!(logger.logs.len(), 3, "Exactly three events should be logged");
        claim!(
            logger.logs.contains(&to_bytes(&OvlEvent::Cis2Event(Cis2Event::Mint(MintEvent {
                owner:    ADDRESS_0,
                token_id: TOKEN_ID_OVL,
                amount:   ContractTokenAmount::from(0),
            })))),
            "Missing event for minting the token"
        );
        claim!(
            logger.logs.contains(&to_bytes(&OvlEvent::Cis2Event(Cis2Event::TokenMetadata::<
                _,
                ContractTokenAmount,
            >(
                TokenMetadataEvent {
                    token_id:     TOKEN_ID_OVL,
                    metadata_url: MetadataUrl {
                        url:  String::from(INITIAL_TOKEN_METADATA_URL),
                        hash: Some(initial_metadata_hash),
                    },
                }
            )))),
            "Missing event with metadata for the token"
        );
        claim!(
            logger.logs.contains(&to_bytes(&OvlEvent::NewAdmin(NewAdminEvent {
                new_admin: ADDRESS_0,
            }))),
            "Missing event for the new admin"
        );
    }

    /// Test only admin can setMetadataUrl
    #[concordium_test]
    #[cfg(feature = "crypto-primitives")]
    fn test_set_metadata_url() {
        let mut logger = TestLogger::init();
        let mut state_builder = TestStateBuilder::new();

        // Set up crypto primitives to hash the document.
        let crypto_primitives = TestCryptoPrimitives::new();
        // The hash of the document stored at the above URL.
        let initial_metadata_hash: Sha256 =
            crypto_primitives.hash_sha2_256("document".as_bytes()).0;

        let metadata_url = concordium_cis2::MetadataUrl {
            url:  INITIAL_TOKEN_METADATA_URL.to_string(),
            hash: Some(initial_metadata_hash),
        };

        let state = State::new(&mut state_builder, ADMIN_ADDRESS, metadata_url);
        let mut host = TestHost::new(state, state_builder);

        // Set up the context
        let mut ctx = TestReceiveContext::empty();
        ctx.set_sender(ADMIN_ADDRESS);

        // Create a new_url and a new_hash
        let new_url = "https://some.example/token/wccd/updated".to_string();
        let new_hash = crypto_primitives.hash_sha2_256("document2".as_bytes()).0;

        // Set up the parameter.
        let parameter = SetMetadataUrlParams {
            url:  new_url.clone(),
            hash: Some(new_hash),
        };
        let parameter_bytes = to_bytes(&parameter);
        ctx.set_parameter(&parameter_bytes);

        // Call the contract function.
        let result = contract_state_set_metadata_url(&ctx, &mut host, &mut logger);
        // Check the result.
        claim!(result.is_ok(), "Results in rejection");

        // Check the logs
        claim_eq!(logger.logs.len(), 1, "Exactly one event should be logged");
        claim!(
            logger.logs.contains(&to_bytes(&OvlEvent::Cis2Event(Cis2Event::TokenMetadata::<
                _,
                ContractTokenAmount,
            >(
                TokenMetadataEvent {
                    token_id:     TOKEN_ID_OVL,
                    metadata_url: MetadataUrl {
                        url:  new_url.clone(),
                        hash: Some(new_hash),
                    },
                }
            )))),
            "Missing event with updated metadata for the token"
        );

        // Check the state.
        let url = host.state().metadata_url.url.clone();
        let hash = host.state().metadata_url.hash;
        claim_eq!(url, new_url, "Expected url being updated");
        claim_eq!(hash, Some(new_hash), "Expected hash being updated");

        // Check only the admin can update the metadata URL
        ctx.set_sender(ADDRESS_0);

        // Call the contract function.
        let err = contract_state_set_metadata_url(&ctx, &mut host, &mut logger);

        // Check that ADDRESS_0 was not successful in updating the metadata url.
        claim_eq!(err, Err(ContractError::Unauthorized), "Error is expected to be Unauthorized")
    }

    #[concordium_test]
    fn test_mint() {
        // Set up the context
        let mut ctx = TestReceiveContext::empty();
        ctx.set_sender(ADMIN_ADDRESS);

        // Set up the parameter.
        let params = MintParams {
            to:       Receiver::from_account(ACCOUNT_1),
            amount:   ContractTokenAmount::from(100),
        };
        let parameter_bytes = to_bytes(&params);
        ctx.set_parameter(&parameter_bytes);

        let mut logger = TestLogger::init();
        let mut state_builder = TestStateBuilder::new();
        let state = initial_state(&mut state_builder);
        let mut host = TestHost::new(state, state_builder);

        // Call the contract function.
        let result: ContractResult<()> = contract_mint(&ctx, &mut host, &mut logger);
        // Check the result.
        claim!(result.is_ok(), "Results in rejection");

        // Check the state.
        let balance1 = host
            .state()
            .balance(&TOKEN_ID_OVL, &ADDRESS_1)
            .expect_report("Token is expected to exist");

        claim_eq!(
            balance1,
            100.into(),
            "Token owner balance should be decreased by the transferred amount"
        );
    }

    #[concordium_test]
    fn test_mint_not_authorized() {
        // Set up the context
        let mut ctx = TestReceiveContext::empty();
        ctx.set_sender(ADDRESS_0);

        // Set up the parameter.
        let params = MintParams {
            to:       Receiver::from_account(ACCOUNT_1),
            amount:   ContractTokenAmount::from(100),
        };
        let parameter_bytes = to_bytes(&params);
        ctx.set_parameter(&parameter_bytes);

        let mut logger = TestLogger::init();
        let mut state_builder = TestStateBuilder::new();
        let state = initial_state(&mut state_builder);
        let mut host = TestHost::new(state, state_builder);

        // Call the contract function.
        let result: ContractResult<()> = contract_mint(&ctx, &mut host, &mut logger);
        // Check the result.
        claim_eq!(result, Err(ContractError::Unauthorized), "Error is expected to be Unauthorized")
    }

    #[concordium_test]
    fn test_burn() {
        // Set up the context
        let mut ctx = TestReceiveContext::empty();
        ctx.set_sender(ADDRESS_0);

        // Set up the parameter.
        let params = BurnParams {
            from:     ADDRESS_0,
            amount:   ContractTokenAmount::from(100),
        };
        let parameter_bytes = to_bytes(&params);
        ctx.set_parameter(&parameter_bytes);

        let mut logger = TestLogger::init();
        let mut state_builder = TestStateBuilder::new();
        let state = initial_state(&mut state_builder);
        let mut host = TestHost::new(state, state_builder);

        // Call the contract function.
        let result: ContractResult<()> = contract_burn(&ctx, &mut host, &mut logger);
        // Check the result.
        claim!(result.is_ok(), "Results in rejection");

        // Check the state.
        let balance0 = host
            .state()
            .balance(&TOKEN_ID_OVL, &ADDRESS_0)
            .expect_report("Token is expected to exist");

        claim_eq!(
            balance0,
            300.into(),
            "Token owner balance should be decreased by the transferred amount"
        );
    }

    #[concordium_test]
    fn test_burn_not_authorized() {
        // Set up the context
        let mut ctx = TestReceiveContext::empty();
        ctx.set_sender(ADDRESS_1);

        // Set up the parameter.
        let params = BurnParams {
            from:     ADDRESS_0,
            amount:   ContractTokenAmount::from(100),
        };
        let parameter_bytes = to_bytes(&params);
        ctx.set_parameter(&parameter_bytes);

        let mut logger = TestLogger::init();
        let mut state_builder = TestStateBuilder::new();
        let state = initial_state(&mut state_builder);
        let mut host = TestHost::new(state, state_builder);

        // Call the contract function.
        let result: ContractResult<()> = contract_burn(&ctx, &mut host, &mut logger);
        // Check the result.
        claim_eq!(result, Err(ContractError::Unauthorized), "Error is expected to be Unauthorized")
    }

    #[concordium_test]
    fn test_burn_insufficient_funds() {
        // Set up the context
        let mut ctx = TestReceiveContext::empty();
        ctx.set_sender(ADDRESS_0);

        // Set up the parameter.
        let params = BurnParams {
            from:     ADDRESS_0,
            amount:   ContractTokenAmount::from(500),
        };
        let parameter_bytes = to_bytes(&params);
        ctx.set_parameter(&parameter_bytes);

        let mut logger = TestLogger::init();
        let mut state_builder = TestStateBuilder::new();
        let state = initial_state(&mut state_builder);
        let mut host = TestHost::new(state, state_builder);

        // Call the contract function.
        let result: ContractResult<()> = contract_burn(&ctx, &mut host, &mut logger);
        // Check the result.
        claim_eq!(result, Err(ContractError::InsufficientFunds), "Error is expected to be InsufficientFunds")
    }

    /// Test transfer succeeds, when `from` is the sender.
    #[concordium_test]
    fn test_transfer_account() {
        // Set up the context
        let mut ctx = TestReceiveContext::empty();
        ctx.set_sender(ADDRESS_0);

        // Set up the parameter.
        let transfer = Transfer {
            token_id: TOKEN_ID_OVL,
            amount:   ContractTokenAmount::from(100),
            from:     ADDRESS_0,
            to:       Receiver::from_account(ACCOUNT_1),
            data:     AdditionalData::empty(),
        };
        let parameter = TransferParams::from(vec![transfer]);
        let parameter_bytes = to_bytes(&parameter);
        ctx.set_parameter(&parameter_bytes);

        let mut logger = TestLogger::init();
        let mut state_builder = TestStateBuilder::new();

        // Set up crypto primitives to hash the document.
        let crypto_primitives = TestCryptoPrimitives::new();
        // The hash of the document stored at the above URL.
        let initial_metadata_hash: Sha256 =
            crypto_primitives.hash_sha2_256("document".as_bytes()).0;

        let metadata_url = concordium_cis2::MetadataUrl {
            url:  INITIAL_TOKEN_METADATA_URL.to_string(),
            hash: Some(initial_metadata_hash),
        };

        let mut state = State::new(&mut state_builder, ADMIN_ADDRESS, metadata_url);
        state
            .mint(&TOKEN_ID_OVL, 400.into(), &ADDRESS_0, &mut state_builder)
            .expect_report("Failed to setup state");
        let mut host = TestHost::new(state, state_builder);

        // Call the contract function.
        let result: ContractResult<()> = contract_transfer(&ctx, &mut host, &mut logger);
        // Check the result.
        claim!(result.is_ok(), "Results in rejection");

        // Check the state.
        let balance0 = host
            .state()
            .balance(&TOKEN_ID_OVL, &ADDRESS_0)
            .expect_report("Token is expected to exist");
        let balance1 = host
            .state()
            .balance(&TOKEN_ID_OVL, &ADDRESS_1)
            .expect_report("Token is expected to exist");
        claim_eq!(
            balance0,
            300.into(),
            "Token owner balance should be decreased by the transferred amount"
        );
        claim_eq!(
            balance1,
            100.into(),
            "Token receiver balance should be increased by the transferred amount"
        );

        // Check the logs.
        claim_eq!(logger.logs.len(), 1, "Only one event should be logged");
        claim_eq!(
            logger.logs[0],
            to_bytes(&OvlEvent::Cis2Event(Cis2Event::Transfer(TransferEvent {
                from:     ADDRESS_0,
                to:       ADDRESS_1,
                token_id: TOKEN_ID_OVL,
                amount:   ContractTokenAmount::from(100),
            }))),
            "Incorrect event emitted"
        )
    }

    /// Test transfer token fails, when sender is neither the owner or an
    /// operator of the owner.
    #[concordium_test]
    fn test_transfer_not_authorized() {
        // Set up the context
        let mut ctx = TestReceiveContext::empty();
        ctx.set_sender(ADDRESS_1);

        // Set up the parameter.
        let transfer = Transfer {
            from:     ADDRESS_0,
            to:       Receiver::from_account(ACCOUNT_1),
            token_id: TOKEN_ID_OVL,
            amount:   ContractTokenAmount::from(100),
            data:     AdditionalData::empty(),
        };
        let parameter = TransferParams::from(vec![transfer]);
        let parameter_bytes = to_bytes(&parameter);
        ctx.set_parameter(&parameter_bytes);

        let mut logger = TestLogger::init();
        let mut state_builder = TestStateBuilder::new();
        let state = initial_state(&mut state_builder);
        let mut host = TestHost::new(state, state_builder);

        // Call the contract function.
        let result: ContractResult<()> = contract_transfer(&ctx, &mut host, &mut logger);
        // Check the result.
        let err = result.expect_err_report("Expected to fail");
        claim_eq!(err, ContractError::Unauthorized, "Error is expected to be Unauthorized")
    }

    /// Test transfer succeeds when sender is not the owner, but is an operator
    /// of the owner.
    #[concordium_test]
    fn test_operator_transfer() {
        // Set up the context
        let mut ctx = TestReceiveContext::empty();
        ctx.set_sender(ADDRESS_1);

        // Set up the parameter.
        let transfer = Transfer {
            from:     ADDRESS_0,
            to:       Receiver::from_account(ACCOUNT_1),
            token_id: TOKEN_ID_OVL,
            amount:   ContractTokenAmount::from(100),
            data:     AdditionalData::empty(),
        };
        let parameter = TransferParams::from(vec![transfer]);
        let parameter_bytes = to_bytes(&parameter);
        ctx.set_parameter(&parameter_bytes);

        let mut logger = TestLogger::init();
        let mut state_builder = TestStateBuilder::new();
        let mut state = initial_state(&mut state_builder);
        state.add_operator(&ADDRESS_0, &ADDRESS_1, &mut state_builder);
        let mut host = TestHost::new(state, state_builder);

        // Call the contract function.
        let result: ContractResult<()> = contract_transfer(&ctx, &mut host, &mut logger);

        // Check the result.
        claim!(result.is_ok(), "Results in rejection");

        // Check the state.
        let balance0 = host
            .state()
            .balance(&TOKEN_ID_OVL, &ADDRESS_0)
            .expect_report("Token is expected to exist");
        let balance1 = host
            .state()
            .balance(&TOKEN_ID_OVL, &ADDRESS_1)
            .expect_report("Token is expected to exist");
        claim_eq!(
            balance0,
            300.into(),
            "Token owner balance should be decreased by the transferred amount"
        );
        claim_eq!(
            balance1,
            100.into(),
            "Token receiver balance should be increased by the transferred amount"
        );

        // Check the logs.
        claim_eq!(logger.logs.len(), 1, "Only one event should be logged");
        claim_eq!(
            logger.logs[0],
            to_bytes(&OvlEvent::Cis2Event(Cis2Event::Transfer(TransferEvent {
                from:     ADDRESS_0,
                to:       ADDRESS_1,
                token_id: TOKEN_ID_OVL,
                amount:   ContractTokenAmount::from(100),
            }))),
            "Incorrect event emitted"
        )
    }

    /// Test adding an operator succeeds and the appropriate event is logged.
    #[concordium_test]
    fn test_add_operator() {
        // Set up the context
        let mut ctx = TestReceiveContext::empty();
        ctx.set_sender(ADDRESS_0);

        // Set up the parameter.
        let update = UpdateOperator {
            operator: ADDRESS_1,
            update:   OperatorUpdate::Add,
        };
        let parameter = UpdateOperatorParams(vec![update]);
        let parameter_bytes = to_bytes(&parameter);
        ctx.set_parameter(&parameter_bytes);

        let mut logger = TestLogger::init();
        let mut state_builder = TestStateBuilder::new();
        let state = initial_state(&mut state_builder);
        let mut host = TestHost::new(state, state_builder);

        // Call the contract function.
        let result: ContractResult<()> = contract_update_operator(&ctx, &mut host, &mut logger);

        // Check the result.
        claim!(result.is_ok(), "Results in rejection");

        // Check the state.
        claim!(host.state().is_operator(&ADDRESS_1, &ADDRESS_0), "Account should be an operator");

        // Checking that `ADDRESS_1` is an operator in the query response of the
        // `contract_operator_of` function as well.
        // Set up the parameter.
        let operator_of_query = OperatorOfQuery {
            address: ADDRESS_1,
            owner:   ADDRESS_0,
        };

        let operator_of_query_vector = OperatorOfQueryParams {
            queries: vec![operator_of_query],
        };
        let parameter_bytes = to_bytes(&operator_of_query_vector);

        ctx.set_parameter(&parameter_bytes);

        // Checking the return value of the `contract_operator_of` function
        let result: ContractResult<OperatorOfQueryResponse> = contract_operator_of(&ctx, &host);

        claim_eq!(
            result.expect_report("Failed getting result value").0,
            [true],
            "Account should be an operator in the query response"
        );

        // Check the logs.
        claim_eq!(logger.logs.len(), 1, "One event should be logged");
        claim_eq!(
            logger.logs[0],
            to_bytes(&OvlEvent::Cis2Event(
                Cis2Event::<ContractTokenId, ContractTokenAmount>::UpdateOperator(
                    UpdateOperatorEvent {
                        owner:    ADDRESS_0,
                        operator: ADDRESS_1,
                        update:   OperatorUpdate::Add,
                    }
                )
            )),
            "Incorrect event emitted"
        )
    }

    /// Test upgrading the smart contract instance.
    #[concordium_test]
    fn test_upgradability() {
        // Set up the context
        let mut ctx = TestReceiveContext::empty();
        ctx.set_sender(ADMIN_ADDRESS);

        let self_address = ContractAddress::new(0, 0);
        ctx.set_self_address(self_address);

        let new_module_ref = ModuleReference::from([0u8; 32]);
        let migration_entrypoint = OwnedEntrypointName::new_unchecked("migration".into());

        // Set up the parameter.
        let parameter = UpgradeParams {
            module:  new_module_ref,
            migrate: Some((migration_entrypoint.clone(), OwnedParameter(Vec::new()))),
        };
        let parameter_bytes = to_bytes(&parameter);
        ctx.set_parameter(&parameter_bytes);

        let mut state_builder = TestStateBuilder::new();
        let state = initial_state(&mut state_builder);
        let mut host = TestHost::new(state, state_builder);

        host.setup_mock_upgrade(new_module_ref, Ok(()));
        host.setup_mock_entrypoint(self_address, migration_entrypoint, MockFn::returning_ok(()));

        // Call the upgrade function.
        let result: ContractResult<()> = contract_upgrade(&ctx, &mut host);

        claim_eq!(result, Ok(()), "The upgrade should have been successful");
    }

    #[concordium_test]
    fn test_upgradability_rejects() {
        // Set up the context
        let mut ctx = TestReceiveContext::empty();
        ctx.set_sender(ADMIN_ADDRESS);

        let new_module_ref = ModuleReference::from([0u8; 32]);

        // Set up the parameter.
        let parameter = UpgradeParams {
            module:  new_module_ref,
            migrate: None,
        };
        let parameter_bytes = to_bytes(&parameter);
        ctx.set_parameter(&parameter_bytes);

        let mut state_builder = TestStateBuilder::new();
        let state = initial_state(&mut state_builder);
        let mut host = TestHost::new(state, state_builder);

        // Make module missing such that the upgrade will fail.
        host.setup_mock_upgrade(new_module_ref, Err(UpgradeError::MissingModule));

        // Call the upgrade function.
        let result: ContractResult<()> = contract_upgrade(&ctx, &mut host);

        // Check upgrade was not successful.
        claim_eq!(
            result,
            Err(ContractError::Custom(CustomContractError::FailedUpgradeMissingModule)),
            "The upgrade should have failed because of the missing module"
        );
    }

    /// Test admin can update to a new admin address.
    #[concordium_test]
    fn test_update_admin() {
        // Set up the context
        let mut ctx = TestReceiveContext::empty();
        ctx.set_sender(ADMIN_ADDRESS);
        let mut logger = TestLogger::init();

        // Set up the parameter.
        let parameter_bytes = to_bytes(&[NEW_ADMIN_ADDRESS]);
        ctx.set_parameter(&parameter_bytes);

        // Set up the state and host.
        let mut state_builder = TestStateBuilder::new();
        let state = initial_state(&mut state_builder);
        let mut host = TestHost::new(state, state_builder);

        // Check the admin state.
        claim_eq!(host.state().admin, ADMIN_ADDRESS, "Admin should be the old admin address");

        // Call the contract function.
        let result: ContractResult<()> = contract_update_admin(&ctx, &mut host, &mut logger);

        // Check the result.
        claim!(result.is_ok(), "Results in rejection");

        // Check the admin state.
        claim_eq!(host.state().admin, NEW_ADMIN_ADDRESS, "Admin should be the new admin address");

        // Check the logs
        claim_eq!(logger.logs.len(), 1, "Exactly one event should be logged");

        // Check the event
        claim!(
            logger.logs.contains(&to_bytes(&OvlEvent::NewAdmin(NewAdminEvent {
                new_admin: NEW_ADMIN_ADDRESS,
            }))),
            "Missing event for the new admin"
        );
    }

    /// Test that only the current admin can update the admin address.
    #[concordium_test]
    fn test_update_admin_not_authorized() {
        // Set up the context.
        let mut ctx = TestReceiveContext::empty();
        // NEW_ADMIN is not the current admin but tries to update the admin variable to
        // its own address.
        ctx.set_sender(NEW_ADMIN_ADDRESS);
        let mut logger = TestLogger::init();

        // Set up the parameter.
        let parameter_bytes = to_bytes(&[NEW_ADMIN_ADDRESS]);
        ctx.set_parameter(&parameter_bytes);

        // Set up the state and host.
        let mut state_builder = TestStateBuilder::new();
        let state = initial_state(&mut state_builder);
        let mut host = TestHost::new(state, state_builder);

        // Check the admin state.
        claim_eq!(host.state().admin, ADMIN_ADDRESS, "Admin should be the old admin address");

        // Call the contract function.
        let result: ContractResult<()> = contract_update_admin(&ctx, &mut host, &mut logger);

        // Check that invoke failed.
        claim_eq!(
            result,
            Err(ContractError::Unauthorized),
            "Update admin should fail because not the current admin tries to update"
        );

        // Check the admin state.
        claim_eq!(host.state().admin, ADMIN_ADDRESS, "Admin should be still the old admin address");
    }

    /// Test pausing the contract.
    #[concordium_test]
    fn test_pause() {
        // Set up the context.
        let mut ctx = TestReceiveContext::empty();
        ctx.set_sender(ADMIN_ADDRESS);

        // Set up the parameter to pause the contract.
        let parameter_bytes = to_bytes(&true);
        ctx.set_parameter(&parameter_bytes);

        // Set up the state and host.
        let mut state_builder = TestStateBuilder::new();
        let state = initial_state(&mut state_builder);
        let mut host = TestHost::new(state, state_builder);

        // Call the contract function.
        let result: ContractResult<()> = contract_set_paused(&ctx, &mut host);

        // Check the result.
        claim!(result.is_ok(), "Results in rejection");

        // Check contract is paused.
        claim_eq!(host.state().paused, true, "Smart contract should be paused");
    }

    /// Test unpausing the contract.
    #[concordium_test]
    fn test_unpause() {
        // Set up the context.
        let mut ctx = TestReceiveContext::empty();
        ctx.set_sender(ADMIN_ADDRESS);

        // Set up the parameter to pause the contract.
        let parameter_bytes = to_bytes(&true);
        ctx.set_parameter(&parameter_bytes);

        // Set up the state and host.
        let mut state_builder = TestStateBuilder::new();
        let state = initial_state(&mut state_builder);
        let mut host = TestHost::new(state, state_builder);

        // Call the contract function.
        let result: ContractResult<()> = contract_set_paused(&ctx, &mut host);

        // Check the result.
        claim!(result.is_ok(), "Results in rejection");

        // Check contract is paused.
        claim_eq!(host.state().paused, true, "Smart contract should be paused");

        // Set up the parameter to unpause the contract.
        let parameter_bytes = to_bytes(&false);
        ctx.set_parameter(&parameter_bytes);

        // Call the contract function.
        let result: ContractResult<()> = contract_set_paused(&ctx, &mut host);

        // Check the result.
        claim!(result.is_ok(), "Results in rejection");

        // Check contract is unpaused.
        claim_eq!(host.state().paused, false, "Smart contract should be unpaused");
    }

    /// Test that only the current admin can pause/unpause the contract.
    #[concordium_test]
    fn test_pause_not_authorized() {
        // Set up the context.
        let mut ctx = TestReceiveContext::empty();
        // NEW_ADMIN is not the current admin but tries to pause/unpause the contract.
        ctx.set_sender(NEW_ADMIN_ADDRESS);

        // Set up the parameter to pause the contract.
        let parameter_bytes = to_bytes(&true);
        ctx.set_parameter(&parameter_bytes);

        // Set up the state and host.
        let mut state_builder = TestStateBuilder::new();
        let state = initial_state(&mut state_builder);
        let mut host = TestHost::new(state, state_builder);

        // Call the contract function.
        let result: ContractResult<()> = contract_set_paused(&ctx, &mut host);

        // Check that invoke failed.
        claim_eq!(
            result,
            Err(ContractError::Unauthorized),
            "Pause should fail because not the current admin tries to invoke it"
        );
    }

    /// Test that one can NOT call non-admin state-mutative functions (mint,
    /// burn, transfer, updateOperator) when the contract is paused.
    #[concordium_test]
    fn test_no_execution_of_state_mutative_functions_when_paused() {
        // Set up the context.
        let mut ctx = TestReceiveContext::empty();
        ctx.set_sender(ADMIN_ADDRESS);

        // Set up the parameter to pause the contract.
        let parameter_bytes = to_bytes(&true);
        ctx.set_parameter(&parameter_bytes);

        // Set up the state and host.
        let mut state_builder = TestStateBuilder::new();
        let state = initial_state(&mut state_builder);
        let mut host = TestHost::new(state, state_builder);

        // Call the contract function.
        let result: ContractResult<()> = contract_set_paused(&ctx, &mut host);

        // Check the result.
        claim!(result.is_ok(), "Results in rejection");

        // Check contract is paused.
        claim_eq!(host.state().paused, true, "Smart contract should be paused");

        let mut logger = TestLogger::init();

        // Call the `transfer` function.
        let result: ContractResult<()> = contract_transfer(&ctx, &mut host, &mut logger);

        // Check that invoke failed.
        claim_eq!(
            result,
            Err(ContractError::Custom(CustomContractError::ContractPaused)),
            "Transfer should fail because contract is paused"
        );

        // Call the `updateOperator` function.
        let result: ContractResult<()> = contract_update_operator(&ctx, &mut host, &mut logger);

        // Check that invoke failed.
        claim_eq!(
            result,
            Err(ContractError::Custom(CustomContractError::ContractPaused)),
            "Update operator should fail because contract is paused"
        );

        // Call the `mint` function.
        let result: ContractResult<()> = contract_mint(&ctx, &mut host, &mut logger);

        // Check that invoke failed.
        claim_eq!(
            result,
            Err(ContractError::Custom(CustomContractError::ContractPaused)),
            "Mint should fail because contract is paused"
        );

        // Call the `mint` function.
        let result: ContractResult<()> = contract_burn(&ctx, &mut host, &mut logger);

        // Check that invoke failed.
        claim_eq!(
            result,
            Err(ContractError::Custom(CustomContractError::ContractPaused)),
            "Burn should fail because contract is paused"
        );
    }
}