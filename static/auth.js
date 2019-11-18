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
let validateEmail = (target) => target.value.length != 0 && !target.validity.typeMismatch
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

let defaultMessages = {
    "in-email": "Invalid email",
    "in-uname": [`Must be between 8 and 128 characters`,"\n\nUsername must only have a-z, A-Z, 0-9, '.', '-', or '_'"],
    "in-pass": [`Must be between 8 and 128 characters`,
        "\n\n" + `Password must only have a-z, A-Z, 0-9, ' ', '!', '"', '#', '$', '%', '&', ''', '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\', ']', '^', '_', '\`', '{', '|', '}', or '~'`,
        "\n\n" + `Password must contain at least one a-z or A-Z`,
        "\n\n" + `Password must contain at least one 0-9`,
        "\n\n" + `Password must contain at least one ' ', '!', '"', '#', '$', '%', '&', ''', '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\', ']', '^', '_', '\`', '{', '|', '}', or '~'`],
    "in-verify":`Password does not match`,
}

tippy.setDefaultProps({
    theme: 'light-border',
})

document.querySelectorAll("input").forEach(input =>
    input.addEventListener("keyup", e => {
        // On Enter Key
        if (e.keyCode == 13) {
            e.preventDefault()
            btnSubmit.click()
        }
    })
)

document.querySelectorAll("custom-input > button").forEach(btn => btn.tabIndex = -1)

enabletip = (e,v) => {
    if (e._tippy) {
        e._tippy.enable()
        e._tippy.setProps(v)
    }
    tippy(e,v)
}

disabletip = e => {
    if (e._tippy) {
        e._tippy.disable()
    }
}

let join = v => {
    if (typeof v == "string") return v
    return v.join("")
}

document.querySelector("#in-email").addEventListener('input', e => {
    if (validateEmail(e.target)) {
        e.target.title = ``
        e.target.nextElementSibling.classList = ["btn btn-success validation-good"]
        disabletip(e.target.nextElementSibling)
    } else {
        e.target.title = `Invalid email`
        e.target.nextElementSibling.classList = ["btn btn-danger validation-bad"]
        enabletip(e.target.nextElementSibling, {content: `<span style='white-space: pre-wrap;'>${defaultMessages["in-email"]}</span>`})
    }
})
document.querySelector("#in-uname").addEventListener('input', e => {
    if (isRegister) {
        let tooltip = ``
        if (e.target.value.length < 8 || e.target.value.length > 128) {
            tooltip += defaultMessages["in-uname"][0]
        }
        if (!validUserName.test(e.target.value)) {
            tooltip += defaultMessages["in-uname"][1]
        }
        if (tooltip.length != 0) {
            e.target.nextElementSibling.classList = ["btn btn-danger validation-bad"]
            enabletip(e.target.nextElementSibling, {content: `<span style='white-space: pre-wrap;'>${tooltip.trim()}</span>`})
        } else {
            e.target.nextElementSibling.classList= ["btn btn-success validation-good"]
            disabletip(e.target.nextElementSibling)
        }
        e.target.title = tooltip.trim()
    }
})

let elemVerify = document.querySelector("#in-verify")
let checkVerify = elem => {
    if (isRegister) {
        if (elem.value != document.querySelector("#in-pass").value) {
            elem.nextElementSibling.classList = ["btn btn-danger validation-bad"]
            elem.title = `Password does not match`
            enabletip(elem.nextElementSibling, {content: `<span style='white-space: pre-wrap;'>`+defaultMessages["in-verify"]+`</span>`})
        } else {
            elem.nextElementSibling.classList = ["btn btn-success validation-good"]
            elem.title = ``
            disabletip(elem.nextElementSibling)
        }
    }
}

document.querySelector("#in-pass").addEventListener('input', e => {
    if (isRegister) {
        let tooltip = ``
        if (e.target.value.length < 8 || e.target.value.length > 128) {
            tooltip = defaultMessages["in-pass"][0]
        }
        if (!validPassword[0].test(e.target.value)) {
            tooltip += defaultMessages["in-pass"][1]
        }
        if (!validPassword[1].test(e.target.value)) {
            tooltip += defaultMessages["in-pass"][2]
        }
        if (!validPassword[2].test(e.target.value)) {
            tooltip += defaultMessages["in-pass"][3]
        }
        if (!validPassword[3].test(e.target.value)) {
            tooltip += defaultMessages["in-pass"][4]
        }
        if (tooltip.length != 0) {
            e.target.nextElementSibling.classList ["btn btn-danger validation-bad"]
            enabletip(e.target.nextElementSibling, {content: `<span style='white-space: pre-wrap;'>`+tooltip.trim()+`</span>`})
        } else {
            e.target.nextElementSibling.classList = ["btn btn-success validation-good"]
            disabletip(e.target.nextElementSibling)
        }
        e.target.title = tooltip.trim()
        checkVerify(elemVerify)
    }
})
document.querySelector("#in-verify").addEventListener('input', e => checkVerify(e.target))

document.querySelector("#toggle-signin").addEventListener('click', e => {
    document.querySelectorAll("input").forEach(input => {
        input.value = ""
        input.title = ""
        if(input.id == "in-email") {
            input.nextElementSibling.classList = ["btn btn-danger validation-bad"]
            enabletip(input.nextElementSibling, {content: `<span style='white-space: pre-wrap;'>${defaultMessages["in-email"]}</span>`})
        } else {
            input.nextElementSibling.classList = []
        }
    })
    isRegister = false
    message.textContent = ""
    let togglableDisplays = document.querySelectorAll(".togglable-display")
    for (let disp of togglableDisplays)
        if (!disp.classList.contains("hide-register"))
            disp.classList.add("hide-register")
})
// Generate click event to initialize page to signin
document.querySelector("#toggle-signin").click()

document.querySelector("#toggle-register").addEventListener('click', e => {
    document.querySelectorAll("input").forEach(input => {
        input.value = ""
        input.title = ""
        if (input.id == "in-verify") {
            input.nextElementSibling.classList = ["btn btn-success validation-good"]
        } else {
            input.nextElementSibling.classList = ["btn btn-danger validation-bad"]
            enabletip(input.nextElementSibling, {content: `<span style='white-space: pre-wrap;'>${join(defaultMessages[input.id])}</span>`})
        }
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
        document.querySelectorAll(".validation-bad").forEach(e => e._tippy.show())
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
        document.querySelectorAll(".validation-bad").forEach(e => e._tippy.show())
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