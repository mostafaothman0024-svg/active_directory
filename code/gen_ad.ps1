param(
    [Parameter(Mandatory = $true)]
    [string]$JSONFile
)

Import-Module ActiveDirectory

# التأكد من وجود ملف JSON
if (-not (Test-Path $JSONFile)) {
    Write-Host "JSON file not found: $JSONFile" -ForegroundColor Red
    exit
}

# قراءة ملف JSON
$json = Get-Content -Path $JSONFile -Raw | ConvertFrom-Json

$Domain = $json.domain


function CreateADGroup {

    param(
        [Parameter(Mandatory = $true)]
        $groupObject
    )

    $name = $groupObject.name

    $existingGroup = Get-ADGroup `
        -Filter "Name -eq '$name'" `
        -ErrorAction SilentlyContinue

    if (-not $existingGroup) {

        New-ADGroup `
            -Name $name `
            -SamAccountName $name `
            -GroupScope Global `
            -GroupCategory Security

        Write-Host "Group created: $name" -ForegroundColor Green
    }
    else {
        Write-Host "Group already exists: $name" -ForegroundColor Yellow
    }
}


function CreateADUser {

    param(
        [Parameter(Mandatory = $true)]
        $userObject
    )

    $name = $userObject.name
    $password = $userObject.password

    # تقسيم الاسم
    $firstname, $lastname = $name.Split(" ", 2)

    # مثال: Bob Smith يصبح bsmith
    $username = (
        $firstname.Substring(0, 1) + $lastname
    ).Replace(" ", "").ToLower()

    $samAccountName = $username

    # UPN الصحيح
    $principalName = "$username@$Domain"

    Write-Host "Creating user with UPN: $principalName"

    # التحقق من وجود مستخدم بنفس SamAccountName
    $existingUser = Get-ADUser `
        -Filter "SamAccountName -eq '$samAccountName'" `
        -Properties UserPrincipalName `
        -ErrorAction SilentlyContinue

    if ($existingUser) {

        Write-Host `
            "User already exists: $samAccountName" `
            -ForegroundColor Yellow

        $createdUser = $existingUser
    }
    else {

        # التحقق من عدم تكرار UPN
        $existingUPN = Get-ADUser `
            -Filter "UserPrincipalName -eq '$principalName'" `
            -ErrorAction SilentlyContinue

        if ($existingUPN) {

            Write-Host `
                "UPN already exists: $principalName" `
                -ForegroundColor Red

            return
        }

        $securePassword = ConvertTo-SecureString `
            $password `
            -AsPlainText `
            -Force

        $createdUser = New-ADUser `
            -Name $name `
            -GivenName $firstname `
            -Surname $lastname `
            -SamAccountName $samAccountName `
            -UserPrincipalName $principalName `
            -AccountPassword $securePassword `
            -Enabled $true `
            -ChangePasswordAtLogon $true `
            -PassThru

        Write-Host `
            "User created: $samAccountName" `
            -ForegroundColor Green
    }

    # إضافة المستخدم إلى مجموعاته
    foreach ($groupName in $userObject.groups) {

        $group = Get-ADGroup `
            -Identity $groupName `
            -ErrorAction SilentlyContinue

        if ($group) {

            try {
                Add-ADGroupMember `
                    -Identity $groupName `
                    -Members $createdUser `
                    -ErrorAction Stop

                Write-Host `
                    "$samAccountName added to $groupName" `
                    -ForegroundColor Green
            }
            catch {
                Write-Host `
                    "Could not add $samAccountName to $groupName : $($_.Exception.Message)" `
                    -ForegroundColor Yellow
            }
        }
        else {
            Write-Host `
                "Group does not exist: $groupName" `
                -ForegroundColor Red
        }
    }
}


# إنشاء المجموعات أولًا
foreach ($group in $json.groups) {
    CreateADGroup -groupObject $group
}

# إنشاء المستخدمين
foreach ($user in $json.users) {
    CreateADUser -userObject $user
}