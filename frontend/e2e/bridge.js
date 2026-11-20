// Synthetic Wails boundary for browser regression tests only. Production uses
// the generated Go bindings unchanged; this is never imported by the app.
export const demoAccounts = [
  {id:'1',title:'GitHub|||Работа',login:'developer@example.com',password:'Synthetic-GitHub!42',updatedAt:1794600000},
  {id:'2',title:'Example.com|||Общие',login:'user@example.com',password:'weak',updatedAt:1794600000},
  {id:'3',title:'Рабочая почта|||Работа',login:'alex@example.test',password:'weak',updatedAt:1},
  {id:'4',title:'Банк Пример|||Финансы',login:'synthetic-user',password:'Synthetic-Bank!842',updatedAt:1794600000},
];
export async function installBridge(page, options = {}) {
  await page.addInitScript(({ accounts, options }) => {
    const copy = value => JSON.parse(JSON.stringify(value));
    const state = { accounts, locked:true, pending:false, calls:[], totp: options.totp ?? true,
      vault:{state:'v2-active', v2ContainerPresent:true,v2BackupPresent:true,preparationFresh:false, ...options.vault},
      storage:{ state:'ready',path:'C:\\Users\\Test\\AppData\\Local\\PasswordSaver\\vaults\\default',legacyPaths:[],format:'v2',algorithm:'AES-256-GCM',backupPresent:true,temporaryFiles:0,diagnostic:'', ...options.storage },
    };
    window.mock = state;
    const later = key => new Promise((resolve, reject) => { state[key] = resolve; state['reject' + key.slice(7)] = reject; });
    const methods = {
      GetStorageLocationStatus:async()=>copy(state.storage),
      GetVaultStatus:async()=>{
        const snapshot = copy(state.vault);
        if(state.deferNextStatus) { state.deferNextStatus = false; return new Promise(resolve => state.releaseStatus = () => resolve(snapshot)); }
        return snapshot;
      },
      SetIdleTimeout:async()=>{},TouchActivity:async()=>{},CheckInactivity:async()=>state.locked,
      LoginV2:async()=>{state.locked=false;state.pending=state.totp;return state.totp;},
      Login:async()=>{state.locked=false;state.pending=state.totp;return state.totp;},
      Verify2FA:async code=>{if(code !== '123456')throw Error('неверный код 2FA');state.pending=false;},
      Logout:async()=>{state.locked=true;state.pending=false;}, IsLocked:async()=>state.locked || state.pending,
      ChangeMasterPassword: async () => {
        if (options.delayPasswordChange) await later('resolvePasswordChange');
        state.locked = true;
        state.pending = false;
      },
      CreateRecoveryKey: async () => options.delayRecoveryKeyCreate
        ? later('resolveRecoveryKeyCreate') : 'PSRK1-synthetic-key-not-a-real-secret',
      VerifyRecoveryKey: async () => {},
      DisableRecoveryKey: async () => {},
      PrepareRecoveryKeyReset: async () => options.delayRecoveryKeyReset
        ? later('resolveRecoveryKeyReset') : 'synthetic-key-confirmation',
      ConfirmRecoveryKeyReset: async () => { state.locked = true; state.pending = false; },
      CancelRecoveryKeyReset: async () => {},
      ExportEncryptedV2Backup: async () => options.delayBackupExport ? later('resolveBackupExport') : 'C:\\Synthetic\\backup.v2.enc',
      SelectExternalV2Backup: async () => 'backup.v2.enc',
      PrepareExternalV2Restore: async () => options.delayExternalRestore ? later('resolveExternalRestore') : ({
        token: 'synthetic-external-token', fileName: 'backup.v2.enc', accountCount: 2,
        totpEnabled: true, primaryPresent: true, backupPresent: true,
      }),
      ConfirmExternalV2Restore: async () => { state.locked = true; state.pending = false; },
      CancelExternalV2Restore: async () => {},
      SelectExternalV2Import: async forImport => {
        state.importMode = forImport;
        if (options.delayImportSelection) return later('resolveImportSelection');
        return options.cancelImportPicker ? {} : { token: 'synthetic-selection', fileName: 'backup.v2.enc' };
      },
      CheckSelectedExternalV2Backup: async () => {
        if (options.delayImportReview) return later('resolveImportReview');
        return {
          token: state.importMode ? 'synthetic-import-review' : '',
          fileName: 'backup.v2.enc', accountCount: 2, totpEnabled: true,
          records: state.importMode ? [
            { index: 0, title: 'GitHub|||Работа', login: 'developer@example.com', conflict: true },
            { index: 1, title: 'Synthetic other service', login: 'source@example.test', conflict: false },
          ] : null,
        };
      },
      ConfirmExternalV2Import: async (_token, choices) => {
        if (options.delayImportConfirm) return later('resolveImportConfirm');
        const separate = choices.some(choice => choice.index === 0 && choice.separate);
        const other = choices.some(choice => choice.index === 1);
        if (separate) state.accounts.push({ id: 'synthetic-imported-0', title: 'GitHub|||Работа', login: 'developer@example.com', password: 'synthetic-duplicate' });
        if (other) state.accounts.push({ id: 'synthetic-imported-1', title: 'Synthetic other service', login: 'source@example.test', password: 'synthetic-new-copy-value' });
        return Number(separate) + Number(other);
      },
      CancelExternalV2Import: async () => {},
      GetAccounts:async()=>{if(state.locked || state.pending)throw Error('locked');if(options.delayAccounts)return later('resolveAccounts');return copy(state.accounts);},
      AddAccount:async(title,login,password)=>{state.accounts.push({id:String(Date.now()),title,login,password,updatedAt:Date.now()/1000});},
      UpdateAccount:async(id,title,login,password)=>{state.accounts=state.accounts.map(a=>a.id===id?{...a,title,login,password}:a);},
      DeleteAccount:async id=>{state.accounts=state.accounts.filter(a=>a.id!==id);},
      Generate2FA:async()=> options.delayTOTP ? later('resolveTOTP') : ({secret:'SYNTHETICSETUPSECRET',qrCode:''}),
      ConfirmAndEnable2FA:async()=>{state.totp=true;},
      OpenStorageFolder:async()=>{}, OpenLegacyStorageFolder:async()=>{},
      SelectLegacyStorageDirectory:async()=>({token:'synthetic-selection',path:'D:\\SyntheticVault',targetPath:state.storage.path}),
      CancelLegacyStorageSelection:async()=>{}, CancelStorageLocationMigration:async()=>{},
      PrepareStorageLocationMigration:async()=>options.delayMigration?later('resolveMigration'):'synthetic-copy-token',
      PrepareSelectedStorageLocationMigration:async()=>options.delayMigration?later('resolveMigration'):'synthetic-copy-token',
      ConfirmStorageLocationMigration:async()=>{state.storage.state='ready';state.storage.legacyPaths=[];},
      PrepareV2VaultRecovery:async()=> 'synthetic-recovery-token', CancelV2VaultRecovery:async()=>{},
      ConfirmV2VaultRecovery:async()=>{state.locked=false;state.pending=state.totp;return state.totp;},
      PrepareV2Migration:async()=>{
        const token = options.delayMigration ? await later('resolveMigration') : 'synthetic-activation';
        state.vault={...state.vault,state:'v1-prepared',v2ContainerPresent:true,preparationFresh:true};
        return token;
      },
      ConfirmV2Migration:async()=>{state.vault.state='v2-active';state.locked=true;},
      BeginCancelV2Preparation:async()=> 'synthetic-cancel', ConfirmCancelV2Preparation:async()=>{state.vault.state='v1-active';},
      CreateV2Vault:async()=>{state.vault.state='v2-active';},
      BeginVaultReset:async()=> 'synthetic-reset', CancelVaultReset:async()=>{}, ResetVault:async()=>{state.accounts=[];state.vault.state='uninitialized';},
    };
    window.go = { main:{ App: new Proxy({}, { get:(_,name)=>async(...args)=>{
      state.calls.push({name,args});
      if(state.errors?.[name])throw Error(state.errors[name]);
      if (!methods[name]) throw Error('Unexpected test bridge call: '+String(name));
      return methods[name](...args);
    } }) } };
  }, {accounts:demoAccounts, options});
}
export async function unlock(page, { totp = true } = {}) {
  await page.getByRole('textbox', { name:'Мастер-пароль',exact:true }).fill('Synthetic-master!42');
  await page.getByRole('button', {name:'Разблокировать',exact:true}).click();
  if(totp) {
    await page.getByRole('textbox', {name:'Код TOTP',exact:true}).fill('123456');
    await page.getByRole('button', {name:'Подтвердить код',exact:true}).click();
  }
  await page.getByRole('heading', {name:'Мои пароли',exact:true}).waitFor();
}
