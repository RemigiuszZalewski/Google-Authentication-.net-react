import './App.css'

function App() {
    
    const handleLoginWithGoogle = () => {
        window.location.href = 'https://localhost:7141/api/account/login/google?returnUrl=http://localhost:5173';
    }

  return (
    <>
      <div>
        <button onClick={handleLoginWithGoogle}>
            Sign in with Google
        </button>
      </div>
    </>
  )
}

export default App
