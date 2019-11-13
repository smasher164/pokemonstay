let isRegister = false
let btnSubmit = document.querySelector("#btn-submit")
let message = document.querySelector(".message")
let validUserName = /^[a-zA-Z\d.\-_]{8,128}$/
let validPassword = [
    /^[a-zA-Z\d !"#$%&'()*+,-./:;<=>?@[\\\]^_`{|}~]{8,128}$/,
    /[a-zA-Z]/,
    /[\d]/,
    /[ !"#$%&'()*+,-./:;<=>?@[\\\]^_`{|}~]/,
]
let validateEmail = (target) => !target.validity.typeMismatch
let validateUsername = (target) => {
    if (!isRegister) return true
    return validUserName.test(target.value)
}
let validatePassword = (target) => {
    if (!isRegister) return true
    for(let re of validPassword) {
        if(!re.test(target.value)) {
            return false
        }
    }
    return true
}
let validateVerify = (target) => {
    if (!isRegister) return true
    return target.value == document.querySelector("#in-pass").value
}
let validateAll = () =>
    validateEmail(document.querySelector("#in-email")) &&
    validateUsername(document.querySelector("#in-uname")) &&
    validatePassword(document.querySelector("#in-pass")) &&
    validateVerify(document.querySelector("#in-verify"))

document.querySelectorAll("input").forEach(input =>
    input.addEventListener("keyup", e => {
        // On Enter Key
        if (e.keyCode == 13) {
            e.preventDefault()
            btnSubmit.click()
        }
    })
)
document.querySelector("#in-email").addEventListener('input', e => {
    if (validateEmail(e.target)) {
        e.target.classList.remove("invalid-input")
        e.target.title = ``
    } else {
        e.target.classList.add("invalid-input")
        e.target.title = `Invalid email`
    }
})
document.querySelector("#in-uname").addEventListener('input', e => {
    if (isRegister) {
        let tooltip = ``
        if (e.target.value.length < 8 || e.target.value.length > 128) {
            tooltip = `Must be between 8 and 128 characters`
        }
        if (!validUserName.test(e.target.value)) {
            tooltip += "\n\nUsername must only have a-z, A-Z, 0-9, '.', '-', or '_'"
        }
        if (tooltip.length != 0) {
            e.target.classList.add("invalid-input")
        } else {
            e.target.classList.remove("invalid-input")
        }
        e.target.title = tooltip.trim()
    }
})
document.querySelector("#in-pass").addEventListener('input', e => {
    if (isRegister) {
        let tooltip = ``
        if (e.target.value.length < 8 || e.target.value.length > 128) {
            tooltip = `Must be between 8 and 128 characters`
        }
        if (!validPassword[0].test(e.target.value)) {
            tooltip += "\n\n" + `Password must only have a-z, A-Z, 0-9, ' ', '!', '"', '#', '$', '%', '&', ''', '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\', ']', '^', '_', '\`', '{', '|', '}', or '~'`
        }
        if (!validPassword[1].test(e.target.value)) {
            tooltip += "\n\n" + `Password must contain at least one a-z or A-Z`
        }
        if (!validPassword[2].test(e.target.value)) {
            tooltip += "\n\n" + `Password must contain at least one 0-9`
        }
        if (!validPassword[3].test(e.target.value)) {
            tooltip += "\n\n" + `Password must contain at least one ' ', '!', '"', '#', '$', '%', '&', ''', '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\', ']', '^', '_', '\`', '{', '|', '}', or '~'`
        }
        if (tooltip.length != 0) {
            e.target.classList.add("invalid-input")
        } else {
            e.target.classList.remove("invalid-input")
        }
        e.target.title = tooltip.trim()
    }
})
document.querySelector("#in-verify").addEventListener('input', e => {
    if (isRegister) {
        if (e.target.value != document.querySelector("#in-pass").value) {
            e.target.classList.add("invalid-input")
            e.target.title = `Password does not match`
        } else {
            e.target.classList.remove("invalid-input")
            e.target.title = ``
        }
    }
})
document.querySelector("#toggle-signin").addEventListener('click', e => {
    document.querySelectorAll("input").forEach(input => {
        input.value = ""
        input.title = ""
        input.classList.remove("invalid-input")
    })
    isRegister = false
    message.textContent = ""
    let togglableDisplays = document.querySelectorAll(".togglable-display")
    for (let disp of togglableDisplays)
        if (!disp.classList.contains("hide-register"))
            disp.classList.add("hide-register")
})
document.querySelector("#toggle-register").addEventListener('click', e => {
    document.querySelectorAll("input").forEach(input => {
        input.value = ""
        input.title = ""
        input.classList.remove("invalid-input")
    })
    isRegister = true
    message.textContent = ""
    let togglableDisplays = document.querySelectorAll(".togglable-display")
    for (let disp of togglableDisplays)
        if (disp.classList.contains("hide-register"))
            disp.classList.remove("hide-register")
})
btnSubmit.addEventListener('click', e => {
    if (isRegister)
        submitRegister(e)
    else
        submitSignIn(e)                
})
let submitRegister = e => {
    let email = document.querySelector("#in-email").value
    let uname = document.querySelector("#in-uname").value
    let pass = document.querySelector("#in-pass").value
    let verify = document.querySelector("#in-verify").value
    if (!validateAll()) {
        message.textContent = "Please correct form fields before submitting."
        return
    }
    var req = new XMLHttpRequest()
    req.responseType = 'json'
    req.addEventListener('load', ev => {
        if (ev.target.status != 200) {
            message.textContent = ev.target.response.err
        } else {
            message.textContent = "Account creation was successful"
            window.location.replace("/")
        }
    })
    req.open('POST', '/auth/create-account')
    req.setRequestHeader("Content-Type", "application/json;charset=UTF-8")
    req.send(JSON.stringify({'email': email, 'username': uname, 'password': pass}))
}
let submitSignIn = e => {
    let email = document.querySelector("#in-email").value
    let pass = document.querySelector("#in-pass").value
    if (!validateAll()) {
        message.textContent = "Please correct form fields before submitting."
        return
    }
    var req = new XMLHttpRequest()
    req.responseType = 'json'
    req.addEventListener('load', ev => {
        if (ev.target.status != 200) {
            message.textContent = ev.target.response.err
        } else {
            message.textContent = "Login was successful"
            window.location.replace("/")
        }
    })
    req.open('POST', '/auth/login')
    req.setRequestHeader("Content-Type", "application/json;charset=UTF-8")
    req.send(JSON.stringify({'email':email, 'password': pass}))
}