package routes

import "github.com/gin-gonic/gin"

func GetToken(c *gin.Context) {
	//	type TokenRequest struct {
	//		Username string `json:"username" binding:"required"`
	//		Password string `json:"password" binding:"required"`
	//	}
	//
	//	type TokenResponse struct {
	//		Token string `json:"token"`
	//	}
	//
	// var tokenRequest TokenRequest
	//
	// err := c.ShouldBindJSON(&tokenRequest)
	//
	//	if err != nil {
	//		log.Println(err)
	//	}
	//
	// token := GetJWT(tokenRequest.Username, tokenRequest.Password)
	//
	//	if token != "incorrect username or password" {
	//		var response TokenResponse
	//		response.Token = token
	//
	//		c.JSON(http.StatusOK, response)
	//	} else {
	//
	//		var response APIResponse
	//		response.Code = 401
	//		response.Message = token
	//
	//		c.JSON(http.StatusUnauthorized, response)
	//	}
}
