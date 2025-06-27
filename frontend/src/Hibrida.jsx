import React, { useState, useRef, useEffect } from 'react';
import { 
    Upload, Send, Mail, KeyRound, Copy, CheckCircle, AlertTriangle, 
    Loader2, Lock, Unlock, Eye, EyeOff, Shield, Download,
    ImageIcon, FileText, Zap, Sparkles, ChevronDown, ChevronUp, X, Settings
} from 'lucide-react';

// === Komponen UI Pembantu ===
const Alert = ({ message, type, onDismiss }) => {
    if (!message) return null;
    const styles = {
        error: { bg: 'bg-red-100', border: 'border-red-500', text: 'text-red-700', icon: AlertTriangle },
        success: { bg: 'bg-green-100', border: 'border-green-500', text: 'text-green-700', icon: CheckCircle },
        info: { bg: 'bg-blue-100', border: 'border-blue-500', text: 'text-blue-700', icon: Shield }
    };
    const style = styles[type] || styles.info;
    const Icon = style.icon;
    return (
        <div className={`mt-4 p-4 rounded-xl border-l-4 ${style.bg} ${style.border} ${style.text} flex items-start justify-between shadow-sm`}>
            <div className="flex items-start gap-3"><Icon className="h-5 w-5 mt-0.5 flex-shrink-0" /><span className="text-sm font-medium">{message}</span></div>
            {onDismiss && <button onClick={onDismiss} className="text-current hover:opacity-70 transition-opacity"><X className="h-4 w-4" /></button>}
        </div>
    );
};

const FeatureCard = ({ icon: Icon, title, description, color }) => {
    const colorClasses = {
        blue: "bg-blue-50 text-blue-700 border-blue-200",
        green: "bg-green-50 text-green-700 border-green-200",
        purple: "bg-purple-50 text-purple-700 border-purple-200",
        amber: "bg-amber-50 text-amber-700 border-amber-200"
    };
    return (
        <div className={`p-4 rounded-xl border ${colorClasses[color]} transition-all duration-200 hover:shadow-md`}>
            <div className="flex items-start gap-3">
                <div className="p-2 bg-white rounded-lg shadow-sm"><Icon className="h-5 w-5" /></div>
                <div><h3 className="font-semibold text-sm">{title}</h3><p className="text-xs opacity-80 mt-1">{description}</p></div>
            </div>
        </div>
    );
};

const TabButton = ({ id, activeTab, setActiveTab, icon, label, color }) => {
    const isActive = activeTab === id;
    const colorClasses = {
        blue: isActive ? 'border-blue-500 text-blue-600 bg-blue-50' : 'hover:text-blue-600 hover:border-blue-300',
        purple: isActive ? 'border-purple-500 text-purple-600 bg-purple-50' : 'hover:text-purple-600 hover:border-purple-300'
    };
    return (
        <button onClick={() => setActiveTab(id)} className={`flex items-center gap-2 font-medium text-lg px-6 py-3 rounded-t-xl border-b-2 transition-all duration-200 ${isActive ? `${colorClasses[color]} shadow-sm` : `border-transparent text-slate-500 ${colorClasses[color]}`}`}>{icon}{label}</button>
    );
};

// === Panel Pengirim (Sender) ===
const SenderPanel = ({ onProcessComplete }) => {
    const [message, setMessage] = useState('');
    const [aesKey, setAesKey] = useState(''); 
    const [coverImage, setCoverImage] = useState(null);
    const [coverPreview, setCoverPreview] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const [error, setError] = useState('');
    const [result, setResult] = useState(null);
    const [showKey, setShowKey] = useState(false);
    
    const outputRef = useRef(null);

    const handleImageChange = (e) => {
        const file = e.target.files[0];
        if (file) {
            setCoverImage(file);
            setCoverPreview(URL.createObjectURL(file));
            setResult(null); // Reset hasil jika gambar diubah
        }
    };
    
    const handleCopyAndSwitch = () => {
        if (!result || !result.keys) return;
        const keyToCopy = result.keys.universalDecryptionKey;
        navigator.clipboard.writeText(keyToCopy).then(() => {
            alert('Kunci Universal berhasil disalin!');
            if (onProcessComplete) {
                onProcessComplete(keyToCopy, result.stegoImage.dataURL);
            }
        }).catch(err => console.error('Gagal menyalin kunci:', err));
    };

    const handleEncrypt = async () => {
        if (!message || !coverImage || aesKey.length !== 16) {
            setError('Pesan (1-16 char), Kunci AES (16 char), dan Gambar Sampul wajib diisi!');
            return;
        }
        setIsLoading(true);
        setError('');
        setResult(null);

        const formData = new FormData();
        formData.append('message', message);
        formData.append('aes_key', aesKey);
        formData.append('image', coverImage);

        try {
            const response = await fetch('http://127.0.0.1:5000/api/encrypt', {
                method: 'POST',
                body: formData,
            });
            const resData = await response.json();
            if (!resData.success) {
                throw new Error(resData.error.message || 'Terjadi kesalahan di server.');
            }
            setResult(resData);
            setTimeout(() => outputRef.current?.scrollIntoView({ behavior: 'smooth' }), 100);
        } catch (err) {
            setError(err.message);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="space-y-6">
            {error && <Alert message={error} type="error" onDismiss={() => setError('')} />}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="space-y-4">
                    <div className="flex items-center gap-2 mb-2"><FileText className="h-5 w-5 text-blue-600" /><label htmlFor="message" className="text-sm font-semibold text-slate-700">Pesan Rahasia (max 16 char)</label></div>
                    <textarea id="message" maxLength={16} rows="3" value={message} onChange={(e) => setMessage(e.target.value)} className="w-full p-4 border border-slate-200 rounded-xl focus:ring-2 focus:ring-blue-500" placeholder="Contoh: 211401001 Budi"/>
                    
                    <div className="flex items-center gap-2 mb-2 pt-2"><KeyRound className="h-5 w-5 text-amber-600" /><label htmlFor="aes_key" className="text-sm font-semibold text-slate-700">Kunci AES (wajib 16 char)</label></div>
                    <input id="aes_key" type="text" maxLength={16} value={aesKey} onChange={(e) => setAesKey(e.target.value)} className="w-full p-4 border border-slate-200 rounded-xl focus:ring-2 focus:ring-amber-500 font-mono" placeholder="Contoh: INIKUNCIRAHASIA1"/>
                </div>
                <div className="space-y-4">
                    <div className="flex items-center gap-2 mb-2"><ImageIcon className="h-5 w-5 text-green-600" /><label className="text-sm font-semibold text-slate-700">Gambar Sampul (Cover Image)</label></div>
                    <div className="border-2 border-dashed border-slate-300 rounded-xl p-6 text-center hover:border-blue-400 h-full flex items-center justify-center">
                        <input type="file" id="cover-image" accept="image/png, image/jpeg" onChange={handleImageChange} className="hidden"/>
                        <label htmlFor="cover-image" className="cursor-pointer">
                            {coverPreview ? <img src={coverPreview} className="rounded-lg max-h-48 mx-auto border shadow-sm" alt="Preview"/> : <div className="space-y-2"><Upload className="h-12 w-12 text-slate-400 mx-auto" /><p>Pilih gambar (.png / .jpg)</p></div>}
                        </label>
                    </div>
                </div>
            </div>
            <button onClick={handleEncrypt} disabled={isLoading || !message || !coverImage || aesKey.length !== 16} className="w-full bg-gradient-to-r from-blue-500 to-purple-600 text-white font-bold py-4 px-6 rounded-xl flex items-center justify-center gap-3 shadow-lg disabled:opacity-50 disabled:cursor-not-allowed transition-opacity">
                {isLoading ? <><Loader2 className="animate-spin h-5 w-5" />Memproses...</> : <><Lock className="h-5 w-5" />Enkripsi & Sembunyikan</>}
            </button>
            
            {result && result.success && (
                <div ref={outputRef} className="mt-8 pt-6 border-t border-slate-200/80 space-y-8 animate-fade-in">
                    <Alert message={result.message} type="success"/>

                    {result.stegoImage && (
                         <div className="space-y-4">
                            <div className="flex items-center gap-2"><ImageIcon className="h-6 w-6 text-green-600" /><h4 className="font-semibold text-xl">Gambar Hasil Steganografi</h4></div>
                             <img src={result.stegoImage.dataURL} className="rounded-xl border-2 w-full object-cover shadow-lg" alt="Gambar Hasil Steganografi"/>
                         </div>
                    )}

                    {result.generationDetails && (
                        <div className="space-y-4">
                            <div className="flex items-center gap-2"><Settings className="h-6 w-6 text-slate-600" /><h4 className="font-semibold text-xl text-slate-700">Detail Proses Generasi</h4></div>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                <div className="bg-slate-50/70 p-4 rounded-xl border"><h5 className="font-bold text-slate-800 mb-3">Parameter RSA</h5><div className="space-y-2 text-sm font-mono break-words text-slate-600"><p><span className="font-semibold text-slate-800">n:</span> {result.generationDetails.rsa.n}</p><p><span className="font-semibold text-red-600">d:</span> {result.generationDetails.rsa.d}</p></div></div>
                                <div className="bg-slate-50/70 p-4 rounded-xl border"><h5 className="font-bold text-slate-800 mb-3">Parameter Schnorr</h5><div className="space-y-2 text-sm font-mono break-words text-slate-600"><p><span className="font-semibold text-red-600">x (privat):</span> {result.generationDetails.schnorr.x}</p><p><span className="font-semibold text-green-600">y (publik):</span> {result.generationDetails.schnorr.y}</p></div></div>
                            </div>
                        </div>
                    )}

                    {result.keys && (
                        <div className="space-y-4 pt-8 border-t border-slate-200/80 border-dashed">
                             <div className="flex items-center justify-between">
                                 <div className="flex items-center gap-2"><KeyRound className="h-6 w-6 text-purple-600" /><h4 className="font-semibold text-xl">Kunci Universal</h4></div>
                                <button onClick={() => setShowKey(!showKey)} className="text-sm flex items-center gap-1 text-slate-600 hover:text-blue-600">{showKey ? <EyeOff size={14}/> : <Eye size={14}/>}{showKey ? 'Sembunyikan' : 'Tampilkan'}</button>
                            </div>
                            <textarea readOnly rows="6" value={result.keys.universalDecryptionKey} className={`w-full p-4 bg-slate-50 border rounded-xl font-mono text-xs transition-all ${!showKey && 'blur-sm'}`}/>
                            <button onClick={handleCopyAndSwitch} className="w-full mt-2 bg-purple-100 text-purple-700 px-4 py-3 rounded-xl flex items-center justify-center gap-2 hover:bg-purple-200 transition-colors font-semibold"><Copy className="h-4 w-4" />Salin & Pindah ke Panel Penerima</button>
                        </div>
                    )}
                </div>
            )}
        </div>
    );
};

// === Panel Penerima (Receiver) ===
const ReceiverPanel = ({ initialKey, initialImageURL, initialImageFile }) => {
    const [universalKey, setUniversalKey] = useState(initialKey || '');
    const [stegoImage, setStegoImage] = useState(initialImageFile || null);
    const [stegoPreview, setStegoPreview] = useState(initialImageURL || '');
    const [isLoading, setIsLoading] = useState(false);
    const [output, setOutput] = useState(null);
    const [error, setError] = useState('');
    const outputRef = useRef(null);
    
    // Sinkronkan state jika prop dari komponen utama berubah
    useEffect(() => {
        setUniversalKey(initialKey || '');
        setStegoPreview(initialImageURL || '');
        setStegoImage(initialImageFile || null);
    }, [initialKey, initialImageURL, initialImageFile]);


    const handleImageChange = (e) => {
        const file = e.target.files[0];
        if (file) {
            setStegoImage(file);
            setStegoPreview(URL.createObjectURL(file));
            setOutput(null);
        }
    };

    const handleDecrypt = async () => {
        if (!universalKey || !stegoImage) {
            setError('Kunci Universal dan Gambar Stego wajib diisi!');
            return;
        }
        setIsLoading(true);
        setError('');
        setOutput(null);
        
        const formData = new FormData();
        formData.append('key', universalKey);
        formData.append('image', stegoImage);
        
        try {
            const response = await fetch('http://127.0.0.1:5000/api/decrypt', {
                method: 'POST',
                body: formData,
            });
            const resData = await response.json();
            if (!resData.success) {
                 throw new Error(resData.error.message || 'Terjadi kesalahan di server.');
            }
            setOutput(resData);
            setTimeout(() => outputRef.current?.scrollIntoView({ behavior: 'smooth' }), 100);
        } catch (err) {
            setError(err.message);
        } finally {
            setIsLoading(false);
        }
    };
    
    const handleDownload = () => {
        if (!output || !output.stegoImage || !output.stegoImage.dataURL) return;
        const link = document.createElement('a');
        link.href = output.stegoImage.dataURL;
        link.download = 'gambar_terverifikasi.png';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
    };
    
    const VerificationStatus = ({ verification }) => {
        const isFullyValid = verification.signature.isValid && verification.fingerprint.isValid;
        const bgColor = isFullyValid ? 'bg-green-100 border-green-200 text-green-800' : 'bg-red-100 border-red-200 text-red-800';
        const Icon = isFullyValid ? CheckCircle : AlertTriangle;
        return (
            <div className={`p-4 rounded-xl border flex flex-col gap-3 shadow-sm ${bgColor}`}>
                 <div className="flex items-center gap-3"><Icon className="h-6 w-6" /><h3 className="font-bold text-lg">Ringkasan Verifikasi</h3></div>
                 <p className="text-sm font-medium">{verification.summary}</p>
                 <div className="text-xs grid grid-cols-2 gap-x-4 gap-y-1 pt-2 border-t border-current/20">
                    <p>Tanda Tangan:</p><p className={`font-bold ${verification.signature.isValid ? 'text-green-900' : 'text-red-900'}`}>{verification.signature.statusText}</p>
                    <p>Sidik Jari:</p><p className={`font-bold ${verification.fingerprint.isValid ? 'text-green-900' : 'text-red-900'}`}>{verification.fingerprint.statusText}</p>
                 </div>
            </div>
        )
    };

    return (
        <div className="space-y-6">
            {error && <Alert message={error} type="error" onDismiss={() => setError('')} />}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="space-y-4">
                    <div className="flex items-center gap-2 mb-2"><KeyRound className="h-5 w-5 text-purple-600" /><label htmlFor="key-input" className="text-sm font-semibold text-slate-700">Kunci Universal</label></div>
                    <textarea id="key-input" rows="8" value={universalKey} onChange={(e) => setUniversalKey(e.target.value)} className="w-full p-4 border border-slate-200 rounded-xl font-mono text-xs" placeholder="Tempelkan Kunci Universal yang Anda terima di sini..."/>
                </div>
                 <div className="space-y-4">
                    <div className="flex items-center gap-2 mb-2"><ImageIcon className="h-5 w-5 text-green-600" /><label className="text-sm font-semibold text-slate-700">Gambar Stego</label></div>
                    <div className="border-2 border-dashed border-slate-300 rounded-xl p-6 text-center hover:border-purple-400 h-full flex items-center justify-center">
                        <input type="file" id="stego-image-input" accept="image/png" onChange={handleImageChange} className="hidden"/>
                        <label htmlFor="stego-image-input" className="cursor-pointer">
                            {stegoPreview ? <img src={stegoPreview} className="rounded-lg max-h-48 mx-auto border shadow-sm" alt="Stego Preview"/> : <div className="space-y-2"><Upload className="h-12 w-12 text-slate-400 mx-auto" /><p>Pilih gambar stego</p></div>}
                        </label>
                    </div>
                </div>
            </div>
            
            <button onClick={handleDecrypt} disabled={isLoading || !universalKey || !stegoImage} className="w-full bg-gradient-to-r from-purple-500 to-indigo-600 text-white font-bold py-4 px-6 rounded-xl flex items-center justify-center gap-3 shadow-lg disabled:opacity-50 disabled:cursor-not-allowed transition-opacity">
                {isLoading ? <><Loader2 className="animate-spin h-5 w-5" />Memverifikasi...</> : <><Unlock className="h-5 w-5" />Buka & Verifikasi Pesan</>}
            </button>
            
            {output && output.success && (
                <div ref={outputRef} className="mt-8 pt-6 border-t border-slate-200/80 grid grid-cols-1 md:grid-cols-2 gap-8 animate-fade-in">
                    <div className="space-y-4">
                        <VerificationStatus verification={output.verification} />
                        <div>
                            <label className="block text-sm font-semibold mb-2 mt-4">Pesan Didekripsi:</label>
                            <div className="w-full p-4 bg-slate-50 border rounded-xl min-h-[100px] text-lg font-semibold">{output.data.decryptedMessage}</div>
                        </div>
                        <div>
                            <label className="block text-sm font-semibold mb-2 text-amber-700">Kunci AES Hasil Dekripsi:</label>
                            <div className="w-full p-4 bg-amber-50 border rounded-xl font-mono text-sm text-amber-900">{output.data.decryptedAesKey}</div>
                        </div>
                    </div>
                    <div className="space-y-4">
                        <div className="flex items-center justify-between">
                            <label className="block text-sm font-semibold">Gambar yang Diverifikasi:</label>
                            {output.stegoImage && (
                                <button onClick={handleDownload} className="flex items-center gap-2 text-sm bg-green-100 text-green-700 px-3 py-1 rounded-lg hover:bg-green-200 transition-colors">
                                    <Download size={14} />Unduh
                                </button>
                            )}
                        </div>
                        {output.stegoImage ? 
                            <img src={output.stegoImage.dataURL} className="rounded-xl border-2 w-full object-cover shadow-lg" alt="Gambar Hasil"/>
                            : <div className="w-full p-4 bg-slate-100 border rounded-xl text-center text-slate-500">Gambar tidak tersedia.</div>
                        }
                    </div>
                </div>
            )}
        </div>
    );
};

// === Komponen Utama Aplikasi ===
export default function App() {
    const [activeTab, setActiveTab] = useState('sender');
    const [showFeatures, setShowFeatures] = useState(false);
    const [universalKey, setUniversalKey] = useState('');
    const [stegoImageURL, setStegoImageURL] = useState('');
    const [stegoImageFile, setStegoImageFile] = useState(null); // State baru untuk file gambar

    // Fungsi helper untuk mengubah data URL menjadi objek File
    const dataURLtoFile = (dataurl, filename) => {
        let arr = dataurl.split(','), mime = arr[0].match(/:(.*?);/)[1],
            bstr = atob(arr[1]), n = bstr.length, u8arr = new Uint8Array(n);
        while(n--){
            u8arr[n] = bstr.charCodeAt(n);
        }
        return new File([u8arr], filename, {type:mime});
    }

    // Fungsi ini dipanggil dari SenderPanel setelah enkripsi berhasil
    const handleProcessComplete = (key, imageUrl) => {
        setUniversalKey(key);
        setStegoImageURL(imageUrl);
        // Konversi imageUrl ke File dan simpan di state
        const file = dataURLtoFile(imageUrl, 'stego_image.png');
        setStegoImageFile(file);
        setActiveTab('receiver');
    };
    
    const featureDescription = "AES-128 & RSA-16bit";

    return (
        <div className="bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100 min-h-screen font-sans text-slate-800">
            <style>{`.animate-fade-in { animation: fadeIn 0.5s ease-in-out; } @keyframes fadeIn { 0% { opacity: 0; transform: translateY(10px); } 100% { opacity: 1; transform: translateY(0); } }`}</style>
            <div className="container mx-auto p-4 md:p-8 max-w-5xl">
                <header className="text-center mb-8">
                    <div className="flex items-center justify-center gap-3 mb-4"><div className="p-3 bg-gradient-to-br from-blue-500 to-purple-600 rounded-2xl shadow-lg"><Shield className="h-8 w-8 text-white" /></div><h1 className="text-3xl md:text-4xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">CryptoStego Pro</h1></div>
                    <p className="text-slate-600 text-lg max-w-2xl mx-auto">Solusi keamanan digital modern dengan kriptografi hibrida dan steganografi canggih.</p>
                    <button onClick={() => setShowFeatures(!showFeatures)} className="mt-4 inline-flex items-center gap-2 text-sm text-slate-600 hover:text-blue-600"><Sparkles className="h-4 w-4" />Fitur Unggulan{showFeatures ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}</button>
                    {showFeatures && <div className="mt-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 animate-fade-in"><FeatureCard icon={Lock} title="Enkripsi Hibrida" description={featureDescription} color="blue" /><FeatureCard icon={ImageIcon} title="Steganografi LSB" description="Sembunyikan data dalam gambar" color="green" /><FeatureCard icon={Shield} title="Tanda Tangan Digital" description="Schnorr Signature" color="purple" /><FeatureCard icon={Zap} title="Performa Cepat" description="Python Backend (Flask)" color="amber" /></div>}
                </header>
                <div className="bg-white/70 backdrop-blur-sm rounded-2xl shadow-xl border border-white/20 p-2 sm:p-6">
                    <div className="mb-6 border-b border-slate-200"><nav className="flex space-x-1"><TabButton id="sender" activeTab={activeTab} setActiveTab={setActiveTab} icon={<Send size={18} />} label="Pengirim" color="blue" /><TabButton id="receiver" activeTab={activeTab} setActiveTab={setActiveTab} icon={<Mail size={18} />} label="Penerima" color="purple" /></nav></div>
                    <div className="p-2 sm:p-0">
                        {activeTab === 'sender' && <SenderPanel onProcessComplete={handleProcessComplete} />}
                        {activeTab === 'receiver' && <ReceiverPanel 
                            initialKey={universalKey} 
                            initialImageURL={stegoImageURL} 
                            initialImageFile={stegoImageFile} // Kirim file ke ReceiverPanel
                        />}
                    </div>
                </div>
            </div>
        </div>
    );
}
