package sdk

const computationsEndpoint = "computations"
const connectEndpoint = "connect"

// func (sdk cSDK) CreateComputation(c Computation, token string) (string, error) {
// 	data, err := json.Marshal(c)
// 	if err != nil {
// 		return "", err
// 	}

// 	url := fmt.Sprintf("%s/%s", sdk.computationsURL, computationsEndpoint)

// 	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(data))
// 	if err != nil {
// 		return "", err
// 	}

// 	resp, err := sdk.sendRequest(req, token, string(CTJSON))
// 	if err != nil {
// 		return "", err
// 	}
// 	defer resp.Body.Close()

// 	if resp.StatusCode != http.StatusCreated {
// 		return "", errors.New("Fail to create")
// 	}

// 	id := strings.TrimPrefix(resp.Header.Get("Location"), fmt.Sprintf("/%s/", computationsEndpoint))
// 	return id, nil
// }
